package resourceexchange

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
)

func decodeText(data []byte, d *decoder) {
	lineNumber := 0
	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		lineNumber++
		value, _, _ := bytes.Cut(line, []byte{'#'})
		value = bytes.TrimSpace(value)
		if len(value) == 0 {
			continue
		}
		location := lineLocation(lineNumber)
		if !d.reserve(location) {
			return
		}
		if len(value) > maxValueBytes {
			d.issue(location, "error", fmt.Sprintf("value exceeds %d bytes", maxValueBytes))
			continue
		}
		entry, err := parseResource(string(value))
		d.collect(location, entry, err)
	}
}

func encodeText(list List) ([]byte, error) {
	size := 0
	for _, entry := range list.Entries {
		size += len(entry.Value) + 1
	}
	if size > MaxFileBytes {
		return nil, fmt.Errorf("encoded file exceeds %d bytes", MaxFileBytes)
	}
	data := make([]byte, 0, size)
	for _, entry := range list.Entries {
		data = append(data, entry.Value...)
		data = append(data, '\n')
	}
	return data, nil
}

func lineLocation(line int) string {
	return "line " + strconv.Itoa(line)
}

var csvHeader = [2]string{"type", "value"}

func decodeCSV(data []byte, d *decoder) {
	if !checkCSVRowBounds(data, d) {
		return
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = len(csvHeader)
	r.ReuseRecord = true
	header, err := r.Read()
	if err != nil || !slices.Equal(header, csvHeader[:]) {
		line := 1
		var parseErr *csv.ParseError
		if errors.As(err, &parseErr) {
			line = parseErr.StartLine
		} else if len(header) > 0 {
			line, _ = r.FieldPos(0)
		}
		d.issue(lineLocation(line), "error", "CSV header must be type,value")
		return
	}
	for {
		fields, err := r.Read()
		if err != nil {
			if err == io.EOF {
				return
			}
			var parseErr *csv.ParseError
			if !errors.As(err, &parseErr) {
				d.issue("file", "error", err.Error())
				return
			}
			location := lineLocation(parseErr.StartLine)
			if !d.reserve(location) {
				return
			}
			d.issue(location, "error", parseErr.Err.Error())
			if parseErr.Err != csv.ErrFieldCount {
				return
			}
			continue
		}
		line, _ := r.FieldPos(0)
		location := lineLocation(line)
		if !d.reserve(location) {
			return
		}
		d.addTyped(location, Entry{Type: fields[0], Value: fields[1]})
	}
}

// Neither field permits newlines. Bound physical rows before encoding/csv can
// allocate per-column metadata or follow a quote across many physical rows.
func checkCSVRowBounds(data []byte, d *decoder) bool {
	const maxCSVRowBytes = 4 * 1024
	lineNumber := 0
	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		lineNumber++
		if len(line) > maxCSVRowBytes {
			d.issue(lineLocation(lineNumber), "error", fmt.Sprintf("CSV row exceeds %d bytes", maxCSVRowBytes))
			return false
		}
		// CSV escapes a literal quote with a pair of quotes, so an odd
		// number cannot form a complete record on this physical line.
		if bytes.Count(line, []byte{'"'})%2 != 0 {
			d.issue(lineLocation(lineNumber), "error", "CSV fields cannot contain newlines or unbalanced quotes")
			return false
		}
	}
	return true
}

func encodeCSV(list List) ([]byte, error) {
	var data bytes.Buffer
	w := csv.NewWriter(&data)
	if err := w.Write(csvHeader[:]); err != nil {
		return nil, err
	}
	var row [2]string
	for _, entry := range list.Entries {
		row[0], row[1] = entry.Type, entry.Value
		if err := w.Write(row[:]); err != nil {
			return nil, err
		}
		if data.Len() > MaxFileBytes {
			return nil, fmt.Errorf("encoded file exceeds %d bytes", MaxFileBytes)
		}
	}
	w.Flush()
	return data.Bytes(), w.Error()
}

const keenJSONVersion = 1

func encodeKeenJSON(list List) ([]byte, error) {
	return json.Marshal(struct {
		Version int `json:"version"`
		List
	}{Version: keenJSONVersion, List: list})
}

func decodeKeenJSON(data []byte, d *decoder) {
	r := json.NewDecoder(bytes.NewReader(data))
	r.UseNumber()
	location := "file"
	fields, err := readKeenJSONObject(r, []string{"version", "name", "entries"}, func(field int) error {
		switch field {
		case 0:
			version, err := readKeenJSONScalar[json.Number](r)
			if err != nil {
				return err
			}
			if string(version) != strconv.Itoa(keenJSONVersion) {
				return errors.New("only KeenProxy resource list version 1 is supported")
			}
		case 1:
			name, err := readKeenJSONScalar[string](r)
			if err != nil {
				return err
			}
			if err := validateName(name); err != nil {
				return err
			}
			d.preview.List.Name = name
		case 2:
			var err error
			location, err = decodeKeenJSONEntries(r, d)
			return err
		}
		return nil
	})
	if d.overLimit {
		return
	}
	if err != nil {
		d.issue(location, "error", err.Error())
		return
	}
	if required := uint8(1<<0 | 1<<2); fields&required != required {
		d.issue("file", "error", "version and entries are required")
		return
	}
	if _, err := r.Token(); err != io.EOF {
		d.issue("file", "error", "trailing data after resource list")
	}
}

func decodeKeenJSONEntries(r *json.Decoder, d *decoder) (string, error) {
	if err := expectKeenJSONDelimiter(r, '['); err != nil {
		return "entries", err
	}
	for i := 0; r.More(); i++ {
		location := "entries[" + strconv.Itoa(i) + "]"
		if !d.reserve(location) {
			// The caller ignores this error because reserve reports the limit.
			return location, errors.New("entry limit reached")
		}
		entry, err := readKeenJSONEntry(r)
		if err != nil {
			return location, err
		}
		d.addTyped(location, entry)
	}
	if err := expectKeenJSONDelimiter(r, ']'); err != nil {
		return "entries", err
	}
	return "file", nil
}

func readKeenJSONEntry(r *json.Decoder) (Entry, error) {
	var entry Entry
	fields, err := readKeenJSONObject(r, []string{"type", "value", "disabled"}, func(field int) error {
		var err error
		switch field {
		case 0:
			entry.Type, err = readKeenJSONScalar[string](r)
		case 1:
			entry.Value, err = readKeenJSONScalar[string](r)
		case 2:
			entry.Disabled, err = readKeenJSONScalar[bool](r)
		}
		return err
	})
	if err != nil {
		return Entry{}, err
	}
	if required := uint8(1<<0 | 1<<1); fields&required != required {
		return Entry{}, errors.New("type and value are required")
	}
	return entry, nil
}

// Token parsing checks exact field spellings and duplicates, and streams the
// entries array instead of allocating it before checking its length.
func readKeenJSONObject(r *json.Decoder, fields []string, readField func(int) error) (uint8, error) {
	if err := expectKeenJSONDelimiter(r, '{'); err != nil {
		return 0, err
	}
	var seen uint8
	for r.More() {
		key, err := readKeenJSONScalar[string](r)
		if err != nil {
			return 0, err
		}
		i := slices.Index(fields, key)
		if i < 0 {
			return 0, errors.New("unknown object field")
		}
		bit := uint8(1 << i)
		if seen&bit != 0 {
			return 0, fmt.Errorf("duplicate field %s", key)
		}
		seen |= bit
		if err := readField(i); err != nil {
			return 0, fmt.Errorf("%s: %w", key, err)
		}
	}
	return seen, expectKeenJSONDelimiter(r, '}')
}

func expectKeenJSONDelimiter(r *json.Decoder, delimiter json.Delim) error {
	token, err := r.Token()
	if err != nil {
		return err
	}
	if token != delimiter {
		return fmt.Errorf("expected %q", delimiter)
	}
	return nil
}

func readKeenJSONScalar[T string | bool | json.Number](r *json.Decoder) (T, error) {
	var zero T
	token, err := r.Token()
	if err != nil {
		return zero, err
	}
	value, ok := token.(T)
	if !ok {
		return zero, fmt.Errorf("expected JSON %T", zero)
	}
	return value, nil
}
