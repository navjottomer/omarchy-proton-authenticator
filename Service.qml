import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// Runs bin/protonauth-list. Each run returns a window of upcoming codes per
// entry, so while the panel is open the helper runs about once every five
// minutes instead of once a second. The panel's clock picks the current code.
Item {
  id: root

  property var settings: ({})
  property string pluginDir: ""
  // Codes per entry requested from the helper (30 s periods: 5 minutes).
  property int window: 10

  property bool ok: false
  property var entries: []
  property var error: null
  property bool refreshing: false
  // Epoch seconds at which the window runs low; see Model.refreshAt().
  property real refreshAt: Infinity

  readonly property string helperPath: {
    var base = String(pluginDir || "")
    if (base.indexOf("file://") === 0) base = base.substring(7)
    if (base.length && base.charAt(base.length - 1) !== "/") base += "/"
    return base + "bin/protonauth-list"
  }

  // Fake accounts from the helper (screenshots / trying the UI). Never reads the vault.
  readonly property bool demoMode: {
    var v = settings ? settings.demoMode : false
    return v === true || v === "true"
  }

  property string _out: ""
  property bool _timedOut: false
  property bool _wantCodes: false

  function _run(args, wantCodes) {
    if (listProcess.running) return
    // Only ever run the helper bundled with this plugin (fixed argv, no shell).
    if (!helperPath || !helperPath.endsWith("/bin/protonauth-list")) return
    refreshing = true
    _out = ""
    _timedOut = false
    _wantCodes = wantCodes
    listProcess.command = [helperPath].concat(args)
    listProcess.running = true
  }

  // Codes for the open panel.
  function refresh() {
    _run(demoMode ? ["--demo", "--window", String(window)] : ["--window", String(window)], true)
  }

  // Health only (deps, vault, keyring) for the bar icon; returns no codes.
  function check() { _run(demoMode ? ["--demo", "--window", "1"] : ["--check"], false) }

  // Called while the panel is open, once a second.
  function tick(nowSec) {
    if (!listProcess.running && nowSec >= refreshAt) refresh()
  }

  // Forget codes (called when the panel closes); keeps the health state.
  function forget() {
    entries = []
    refreshAt = Infinity
  }

  function apply() {
    var parsed = _timedOut
      ? { ok: false, entries: [], error: { code: "HELPER_TIMEOUT", message: "Helper timed out" } }
      : Model.parseList(_out)
    _out = ""
    ok = parsed.ok === true
    error = parsed.error || null
    if (_wantCodes) {
      entries = parsed.entries || []
      // On failure, retry in 10 s rather than on every tick.
      refreshAt = ok ? Model.refreshAt(entries) : Date.now() / 1000 + 10
    }
    refreshing = false
  }

  // stdout: one JSON document from our own helper, which caps it at
  // MAX_OUTPUT_BYTES and stops itself after HELPER_TIMEOUT_SEC.
  Process {
    id: listProcess
    running: false
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root._out = text
    }
    onExited: root.apply()
  }

  // Backstop for a helper that hangs anyway: SIGTERM, which the helper turns
  // into a clean exit (temp dir removed).
  Timer {
    interval: 30000
    running: listProcess.running
    onTriggered: { root._timedOut = true; listProcess.running = false }
  }
}
