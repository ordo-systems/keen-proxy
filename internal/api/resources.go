package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/resourceexchange"
)

// The export request includes JSON field and activation overhead beyond the
// resource file itself, even when the destination format is compact.
const maxResourceExportBytes = 8 << 20

const resourceRequestTooLarge = "resource request body is too large"

var (
	errInvalidResourceList = errors.New("invalid resource list request")
	errResourceEntryLimit  = errors.New("too many resource entries")
)

// resourceExchange bounds both conversions under one per-server gate. The
// conversion functions only receive file/list data and cannot access config.
func (s *Server) resourceExchange(mediaType string, bodyLimit int64, convert func(http.ResponseWriter, resourceexchange.Format, io.Reader)) http.Handler {
	authorized := s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !s.resourceBusy.CompareAndSwap(false, true) {
			rejectResourceRequest(w, r, http.StatusServiceUnavailable, "another file conversion is in progress")
			return
		}
		defer s.resourceBusy.Store(false)

		query, err := url.ParseQuery(r.URL.RawQuery)
		formats := query["format"]
		if err != nil || len(query) != 1 || len(formats) != 1 {
			rejectResourceRequest(w, r, http.StatusBadRequest, "expected a single resource format parameter")
			return
		}
		format := resourceexchange.Format(formats[0])
		switch format {
		case resourceexchange.Text, resourceexchange.CSV, resourceexchange.JSON, resourceexchange.SingBox, resourceexchange.SRS:
		default:
			rejectResourceRequest(w, r, http.StatusBadRequest, "unsupported resource format")
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != mediaType {
			rejectResourceRequest(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: "+mediaType)
			return
		}
		if r.ContentLength > bodyLimit {
			rejectResourceRequest(w, r, http.StatusRequestEntityTooLarge, resourceRequestTooLarge)
			return
		}

		setFileConversionDeadlines(w)
		convert(w, format, http.MaxBytesReader(w, r.Body, bodyLimit))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		authorized.ServeHTTP(w, r)
	})
}

// A stalled upload or download must not hold the conversion gate indefinitely.
func setFileConversionDeadlines(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	readDeadline := time.Now().Add(time.Minute)
	_ = controller.SetReadDeadline(readDeadline)
	_ = controller.SetWriteDeadline(readDeadline.Add(time.Minute))
}

func rejectResourceRequest(w http.ResponseWriter, r *http.Request, status int, message string) {
	// Avoid draining an unread HTTP/1 body just to keep a connection reusable.
	if r.ProtoMajor == 1 && r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
	}
	writeError(w, status, message)
}

func resourceBodyError(w http.ResponseWriter, err error, message string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, resourceRequestTooLarge)
		return
	}
	writeError(w, http.StatusBadRequest, message)
}

// previewResources reports invalid file content as diagnostics, not a transport error.
func previewResources(w http.ResponseWriter, format resourceexchange.Format, body io.Reader) {
	data, err := io.ReadAll(body)
	if err != nil {
		resourceBodyError(w, err, "cannot read resource file")
		return
	}
	writeJSON(w, http.StatusOK, resourceexchange.Decode(format, data))
}

func exportResources(w http.ResponseWriter, format resourceexchange.Format, body io.Reader) {
	list, err := readResourceList(body)
	if errors.Is(err, errResourceEntryLimit) {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		resourceBodyError(w, err, errInvalidResourceList.Error())
		return
	}
	data, losses, err := resourceexchange.Encode(format, list)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if losses == nil {
		losses = []string{}
	}
	writeJSON(w, http.StatusOK, struct {
		Data   []byte   `json:"data"`
		Losses []string `json:"losses"`
	}{Data: data, Losses: losses})
}

// Read entries individually: the byte limit alone would still allow millions
// of empty objects to expand into a large []resourceexchange.Entry.
func readResourceList(body io.Reader) (list resourceexchange.List, err error) {
	dec := json.NewDecoder(body)
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return list, err
	}
	if first != json.Delim('{') {
		return list, errInvalidResourceList
	}

	var haveName, haveEntries bool
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return list, err
		}
		switch {
		case key == "name" && !haveName:
			haveName = true
			list.Name, err = readResourceScalar[string](dec)
		case key == "entries" && !haveEntries:
			haveEntries = true
			err = readResourceEntries(dec, &list.Entries)
		default:
			return list, errInvalidResourceList
		}
		if err != nil {
			return list, err
		}
	}
	if !haveEntries {
		return list, errInvalidResourceList
	}
	if _, err := dec.Token(); err != nil {
		return list, err
	}
	// Read through trailing whitespace to EOF so it also counts toward the limit.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errInvalidResourceList
		}
		return list, err
	}
	return list, nil
}

func readResourceEntries(dec *json.Decoder, entries *[]resourceexchange.Entry) error {
	first, err := dec.Token()
	if err != nil {
		return err
	}
	if first != json.Delim('[') {
		return errInvalidResourceList
	}
	for dec.More() {
		if len(*entries) >= resourceexchange.MaxEntries {
			return errResourceEntryLimit
		}
		entry, err := readResourceEntry(dec)
		if err != nil {
			return err
		}
		*entries = append(*entries, entry)
	}
	_, err = dec.Token()
	return err
}

func readResourceEntry(dec *json.Decoder) (entry resourceexchange.Entry, err error) {
	first, err := dec.Token()
	if err != nil {
		return entry, err
	}
	if first != json.Delim('{') {
		return entry, errInvalidResourceList
	}

	// Decode tokens instead of a struct so fields are exact, unique and non-null.
	var haveType, haveValue, haveDisabled bool
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return entry, err
		}
		switch {
		case key == "type" && !haveType:
			haveType = true
			entry.Type, err = readResourceScalar[string](dec)
		case key == "value" && !haveValue:
			haveValue = true
			entry.Value, err = readResourceScalar[string](dec)
		case key == "disabled" && !haveDisabled:
			haveDisabled = true
			entry.Disabled, err = readResourceScalar[bool](dec)
		default:
			return entry, errInvalidResourceList
		}
		if err != nil {
			return entry, err
		}
	}
	if !haveType || !haveValue {
		return entry, errInvalidResourceList
	}
	_, err = dec.Token()
	return entry, err
}

func readResourceScalar[T string | bool](dec *json.Decoder) (value T, err error) {
	token, err := dec.Token()
	if err != nil {
		return value, err
	}
	value, ok := token.(T)
	if !ok {
		return value, errInvalidResourceList
	}
	return value, nil
}
