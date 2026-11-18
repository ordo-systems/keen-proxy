# Browser demo

<a class="md-button md-button--primary" href="../demo/">Open the interactive demo</a>

The demo is built from this repository's real Vue components, styles, translations, and shared draft store. Only the API implementation and static-host routing change. It is a separate build, not a second interface maintained by hand.

The initial footer and build details show the planned release preview from `web/src/demo/release.json`, not a claim that its binaries are published. Release Please keeps this preview identity synchronized when preparing a release. The update and rollback actions remain synthetic examples.

Try editing a group, inspecting a connection, previewing a sample preset, selecting client policies, Apply/Discard, or running simulated diagnostics. Switch English/Russian and the theme from the toolbar.

- Configuration is kept in this page's memory and resets on reload.
- The demo does not contact a router or proxy server, query DNS, fetch filter lists, or perform connectivity checks.
- In **Settings → DNS → Advanced settings → Bypass DNS interception for source IPs**, edit or remove the sample `192.0.2.53` and choose **Apply**. Navigate away and reopen DNS settings to verify the change. This only changes the demo configuration; no firewall rules are installed and no DNS packets are sent. See [DNS interception exceptions](routing.md#dns) for the router behavior.
- Never enter actual credentials. Use the supplied placeholders.
- The monitor simulates traffic every three seconds. The routing journal receives new synthetic events and supports live pause, filters, and pagination. Apply adds an audit entry. The catalog contains one synthetic preset.
- **Logs → Audit** includes synthetic recovery from the netfilter hook, recovery from the watchdog timer, failed verification, and a historical record with no source metadata. The Who column keeps the filterable actor and shows the recovery trigger beneath it; expand an entry for the rule, exit code and raw error. Durations are simulated check-and-recovery times, not measured outages. These examples do not invoke real hooks or change firewall rules.
- **Overview** shows simulated CPU and memory for the router and the KeenProxy process. **Settings → Updates** starts at the planned version, with no newer release advertised. Roll back to the earlier simulated version first, then try returning to the planned version manually or save an automatic update time. Choose the next minute on the displayed UTC clock to see a scheduled installation while the section is open. The demo does not download a release or restart a service.
- **Diagnostics → Download report** exports synthetic check results. To collect retained journals and applied settings as a ZIP, use the [Diagnostics archive](troubleshooting.md#download-the-diagnostic-zip) on the router.
- YAML import is unavailable. Synthetic exports are JSON, which is compatible with YAML 1.2, rather than a production backup format.
- AWG `.conf` editing can be explored with synthetic profiles. Decoding standalone Amnezia `vpn://` exports requires the Go backend and is unavailable in this static demo; the local `make ui-demo` uses the same planned version and provides the real offline decoder.
- Try creating a local preset, saving a local copy of the sample catalog preset, and copying resources into a draft group. [Resource file conversion](user-guide.md#resource-lists) uses the Go backend and is available in the router panel and `make ui-demo`, not the static demo.

The production build continues using the authenticated HTTP API. [Build instructions](development.md) explain how both outputs are created.
