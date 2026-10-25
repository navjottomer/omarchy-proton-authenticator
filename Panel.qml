import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "Model.js" as Model

// Proton Authenticator codes in the bar. Clicking the icon opens a
// launcher-style panel: the search field has focus straight away, typing
// filters, Enter copies. Styled like the stock panels (and navjottomer.sysmon):
// every colour comes from the theme, and the chrome is the shared qs.Ui kit.
//
// Keys (handled by the search field; PanelKeyCatcher is not used because it
// eats j/k/h/l/x/space before they reach a text field):
//   Up/Down, Ctrl+J/K  move         Enter        copy current code
//   PgUp/PgDn          move by 5    Shift+Enter  copy next code
//   Tab/Shift+Tab      next panel   Ctrl+P       pin / unpin
//   Esc                close
Panel {
  id: root

  moduleName: "navjottomer.proton-authenticator"
  ipcTarget: "navjottomer.proton-authenticator"
  manageIpc: false

  readonly property string ff: bar ? bar.fontFamily : Style.font.family
  readonly property color dimForeground: Qt.darker(barForeground, 1.4)
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property bool healthy: svc.ok

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  property string searchText: ""
  property int selectedIndex: 0
  property string copiedKey: ""
  property real nowSec: Date.now() / 1000

  // Clipboard bookkeeping (see copyCode / clearClipboardIfOurs).
  property string _clipboardCode: ""
  property string _pendingCopy: ""
  property string _pendingCheck: ""
  property string _checkingCode: ""

  readonly property string pluginDir: {
    var s = String(Qt.resolvedUrl("."))
    if (s.indexOf("file://") === 0) s = s.substring(7)
    return s
  }
  readonly property string clipcheckPath: {
    var base = pluginDir
    if (base.length && base.charAt(base.length - 1) !== "/") base += "/"
    return base + "bin/protonauth-clipcheck"
  }

  function boolSetting(name, fallback) {
    var v = settings ? settings[name] : undefined
    if (v === undefined || v === null || v === "") return fallback
    return v === true || v === "true"
  }
  readonly property bool closeOnCopy: boolSetting("closeOnCopy", true)
  readonly property bool notifyOnCopy: boolSetting("notifyOnCopy", true)
  readonly property string sortMode: {
    var v = String(settings && settings.sortMode || "recent")
    return (v === "alpha" || v === "vault") ? v : "recent"
  }
  readonly property int clipboardClearSec: {
    var raw = settings ? settings.clipboardClearSec : undefined
    var n = parseInt(String(raw === undefined || raw === null ? 20 : raw), 10)
    if (!isFinite(n) || n < 0) n = 20
    return Math.min(n, 600)
  }

  Component.onCompleted: {
    loadPrefs()
    loadLock()
    svc.check()
  }

  // ---------- Lock ----------
  // Optional password gate in front of the codes, set up in the panel's Lock
  // settings. Nothing is fetched while locked, and "unlocked" lives in memory
  // only, so restarting the shell locks it again. The password is hashed by
  // bin/protonauth-prefs (scrypt, salted) and only ever passed on stdin.
  // This keeps a passer-by out of the panel; it does not encrypt the vault,
  // which any program running as you can still read.
  property bool lockReady: false     // lock-status has been read
  property bool lockSet: false       // a password exists
  property int unlockMinutes: 10     // 0 = lock as soon as the panel closes
  property bool unlocked: false
  property bool lockError: false
  property int lockFailures: 0
  property int lockoutLeft: 0        // seconds the password field stays disabled
  property bool showSettings: false
  property string settingsMsg: ""
  property bool settingsMsgError: false
  property string _lockOut: ""
  property string _lockAction: ""    // "set" | "remove" | "minutes"
  property string _pendingStdin: ""
  readonly property bool granted: lockReady && (!lockSet || unlocked)
  readonly property string lockToolPath: {
    var base = pluginDir
    if (base.length && base.charAt(base.length - 1) !== "/") base += "/"
    return base + "bin/protonauth-prefs"
  }

  // Runs a lock-* command of the prefs helper, feeding it `input` on stdin.
  function runLock(proc, cmd, input) {
    if (proc.running || !lockToolPath.endsWith("/bin/protonauth-prefs")) return false
    _pendingStdin = input
    proc.command = [lockToolPath, cmd]
    proc.stdinEnabled = input.length > 0
    proc.running = true
    return true
  }

  function loadLock() { runLock(lockStatus, "lock-status", "") }

  function tryUnlock() {
    if (lockoutLeft > 0 || passwordField.text.length === 0) return
    if (!runLock(lockVerify, "lock-verify", passwordField.text)) return
    passwordField.text = ""
  }

  function onVerified(ok) {
    if (!ok) {
      lockFailures += 1
      lockError = true
      // Free for the first few tries, then 5 s more per miss, up to 30 s.
      if (lockFailures >= 3) lockoutLeft = Math.min(30, (lockFailures - 2) * 5)
      return
    }
    lockFailures = 0
    lockError = false
    markUnlocked()
  }

  function markUnlocked() {
    unlocked = true
    if (unlockMinutes > 0) lockTimer.restart()
    refresh()
    Qt.callLater(function() { if (root.opened) searchField.forceActiveFocus() })
  }

  function lock() {
    lockTimer.stop()
    unlocked = false
    lockError = false
    showSettings = false
    clearSettingsFields()
    searchText = ""
    searchField.text = ""
    passwordField.text = ""
    svc.forget()
    if (opened) Qt.callLater(function() { passwordField.forceActiveFocus() })
  }

  function clearSettingsFields() {
    currentField.text = ""
    newField.text = ""
    confirmField.text = ""
    settingsMsg = ""
  }

  function openSettings() {
    clearSettingsFields()
    showSettings = true
    Qt.callLater(function() { (root.lockSet ? currentField : newField).forceActiveFocus() })
  }

  function closeSettings() {
    showSettings = false
    clearSettingsFields()
    Qt.callLater(function() { searchField.forceActiveFocus() })
  }

  function savePassword(remove) {
    if (!remove) {
      if (newField.text.length < 4) { showSettingsMsg("Use at least 4 characters", true); return }
      if (newField.text !== confirmField.text) { showSettingsMsg("Passwords don't match", true); return }
    }
    var doc = { password: remove ? "" : newField.text }
    if (lockSet) doc.current = currentField.text
    _lockAction = remove ? "remove" : "set"
    if (!runLock(lockSetProc, "lock-set", JSON.stringify(doc))) return
    currentField.text = ""
    newField.text = ""
    confirmField.text = ""
  }

  function saveMinutes(n) {
    _lockAction = "minutes"
    runLock(lockSetProc, "lock-set", JSON.stringify({ minutes: n }))
  }

  function showSettingsMsg(text, isError) {
    settingsMsg = text
    settingsMsgError = isError
  }

  function onLockSet(result) {
    if (result === "ok") {
      var action = _lockAction
      loadLock()
      if (action === "set") {
        // Setting or changing the password must not lock you out of the panel.
        lockSet = true
        showSettingsMsg("Password saved", false)
        markUnlocked()
      } else if (action === "remove") {
        showSettingsMsg("Password removed. The panel is open to anyone.", false)
      } else {
        showSettingsMsg("Saved", false)
      }
    } else if (result === "bad-current") {
      showSettingsMsg("Current password is wrong", true)
    } else if (result === "bad-length") {
      showSettingsMsg("Use 4 to 256 characters", true)
    } else {
      showSettingsMsg("Could not save", true)
    }
  }

  Process {
    id: lockStatus
    running: false
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root._lockOut = text
    }
    onExited: {
      try {
        var d = JSON.parse(root._lockOut.length <= 1024 ? root._lockOut : "")
        root.lockSet = d.set === true
        var n = parseInt(d.minutes, 10)
        root.unlockMinutes = (isFinite(n) && n >= 0 && n <= 1440) ? n : 10
      } catch (e) {
        root.lockSet = false
      }
      root._lockOut = ""
      root.lockReady = true
    }
  }

  Process {
    id: lockVerify
    running: false
    command: []
    stdinEnabled: false
    stdout: StdioCollector {
      id: lockVerifyOut
      waitForEnd: true
    }
    onStarted: {
      write(root._pendingStdin)
      root._pendingStdin = ""
      stdinEnabled = false
    }
    onExited: {
      root._pendingStdin = ""
      stdinEnabled = false
      root.onVerified(lockVerifyOut.text === "ok\n")
    }
  }

  Process {
    id: lockSetProc
    running: false
    command: []
    stdinEnabled: false
    stdout: StdioCollector {
      id: lockSetOut
      waitForEnd: true
    }
    onStarted: {
      write(root._pendingStdin)
      root._pendingStdin = ""
      stdinEnabled = false
    }
    onExited: {
      root._pendingStdin = ""
      stdinEnabled = false
      root.onLockSet(lockSetOut.text.trim())
    }
  }

  Timer {
    id: lockTimer
    interval: Math.max(1, root.unlockMinutes) * 60 * 1000
    onTriggered: root.lock()
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.lockoutLeft > 0
    onTriggered: root.lockoutLeft -= 1
  }

  // ---------- Pins and recent use ----------
  // Stored as entry keys (vault ids) only, never codes or seeds. All file
  // access goes through bin/protonauth-prefs, which keeps the state folder
  // private (0700, owned by you, no symlinks) and writes via temp file +
  // rename. Read once at startup; this panel is the only writer.
  property var pins: ({})
  property var used: ({})
  property bool _prefsDirty: false   // changed while a write was running
  property bool _prefsTouched: false // changed since startup
  readonly property string prefsToolPath: {
    var base = pluginDir
    if (base.length && base.charAt(base.length - 1) !== "/") base += "/"
    return base + "bin/protonauth-prefs"
  }

  function loadPrefs() {
    if (prefsRead.running || !prefsToolPath.endsWith("/bin/protonauth-prefs")) return
    prefsRead.command = [prefsToolPath, "read"]
    prefsRead.running = true
  }

  // One write at a time; a change made while one is running is written next.
  function savePrefs() {
    if (!prefsToolPath.endsWith("/bin/protonauth-prefs")) return
    _prefsTouched = true
    if (prefsWrite.running) { _prefsDirty = true; return }
    _prefsDirty = false
    prefsWrite.command = [prefsToolPath, "write"]
    prefsWrite.stdinEnabled = true
    prefsWrite.running = true
  }

  Process {
    id: prefsRead
    running: false
    command: []
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        // A change made before the read finished wins over the stored copy.
        if (root._prefsTouched) return
        try {
          var d = JSON.parse(text.length <= 262144 ? text : "")
          root.pins = (d && typeof d.pins === "object" && d.pins) ? d.pins : {}
          root.used = (d && typeof d.used === "object" && d.used) ? d.used : {}
        } catch (e) {
          root.pins = {}
          root.used = {}
        }
      }
    }
  }

  Process {
    id: prefsWrite
    running: false
    command: []
    stdinEnabled: false
    onStarted: {
      write(JSON.stringify({ pins: root.pins, used: root.used }) + "\n")
      stdinEnabled = false // EOF: the helper has the document
    }
    onExited: {
      stdinEnabled = false
      if (root._prefsDirty) root.savePrefs()
    }
  }

  function togglePin(entry) {
    var key = Model.entryKey(entry)
    if (!key) return
    var next = Object.assign({}, pins)
    if (next[key]) delete next[key]
    else next[key] = true
    pins = next
    savePrefs()
  }

  function markUsed(entry) {
    var key = Model.entryKey(entry)
    if (!key) return
    var next = Object.assign({}, used)
    next[key] = Math.floor(Date.now() / 1000)
    used = next
    savePrefs()
  }

  // ---------- List ----------
  readonly property var rows: Model.rankEntries(svc.entries, searchText, pins, used, sortMode)
  readonly property var selectedRow: rows.length ? rows[Math.min(selectedIndex, rows.length - 1)] : null
  readonly property var selectedState: selectedRow ? Model.codeState(selectedRow.entry, nowSec) : null

  readonly property string statusLine: {
    if (svc.refreshing && svc.entries.length === 0) return "Loading…"
    if (!svc.ok && svc.error) return Model.errorHint(svc.error)
    if (rows.length === 0) return searchText.length ? "No matches" : "No accounts"
    return ""
  }

  onSearchTextChanged: {
    selectedIndex = 0
    listFlick.contentY = 0
  }

  function refresh() { if (granted) svc.refresh() }

  function moveCursor(dy) {
    if (rows.length === 0) return
    selectedIndex = Math.max(0, Math.min(rows.length - 1, selectedIndex + dy))
    scrollCursorIntoView()
  }

  // Keyboard moves only: hover also sets selectedIndex, and scrolling under a
  // hovering mouse would make the list lurch.
  function scrollCursorIntoView() {
    Qt.callLater(function() {
      var item = entryRepeater.itemAt(selectedIndex)
      if (!item) return
      var top = item.y
      var bottom = top + item.height
      var maxY = Math.max(0, listFlick.contentHeight - listFlick.height)
      if (top < listFlick.contentY)
        listFlick.contentY = Math.max(0, top)
      else if (bottom > listFlick.contentY + listFlick.height)
        listFlick.contentY = Math.min(maxY, bottom - listFlick.height)
    })
  }

  function copySelected(useNext) {
    var row = selectedRow
    if (!row) return
    var st = Model.codeState(row.entry, nowSec)
    copyCode(row.entry, useNext ? st.next : st.code, useNext)
  }

  function copyCode(entry, code, isNext) {
    code = String(code || "").replace(/\s+/g, "")
    if (!/^[0-9]{1,10}$/.test(code)) return
    copiedKey = Model.entryKey(entry)
    markUsed(entry)
    // --sensitive asks clipboard managers that honour the hint not to keep it.
    // The code goes in on stdin, never on argv: wl-copy stays running in the
    // background and its command line is visible to every user via ps/procfs.
    _pendingCopy = code
    copyProcess.command = ["wl-copy", "--sensitive"]
    copyProcess.stdinEnabled = true
    copyProcess.running = true
    _clipboardCode = code
    if (clipboardClearSec > 0) clipboardClearTimer.restart()
    if (notifyOnCopy) {
      var label = String(entry.issuer || "Account")
      if (entry.account) label += " · " + String(entry.account)
      Quickshell.execDetached(["notify-send", "-a", "Authenticator", "-t", "2000",
        isNext ? "Copied next code" : "Copied code", label])
    }
    if (closeOnCopy) closeAfterCopy.restart()
    else copiedTimer.restart()
  }

  // Clear the clipboard after clipboardClearSec, but only if it still holds
  // the code we put there. The clipboard is never read into this long-lived
  // process: bin/protonauth-clipcheck compares it and prints match/nomatch.
  function clearClipboardIfOurs() {
    if (!_clipboardCode || clipboardCheck.running) return
    if (!/^[0-9]{1,10}$/.test(_clipboardCode)) { _clipboardCode = ""; return }
    if (!clipcheckPath.endsWith("/bin/protonauth-clipcheck")) return
    _pendingCheck = _clipboardCode
    _checkingCode = _clipboardCode
    clipboardCheck.command = ["/bin/sh", clipcheckPath]
    clipboardCheck.stdinEnabled = true
    clipboardCheck.running = true
  }

  function openApp() {
    // Detached so the app outlives the shell; WebKit needs the DMABUF
    // workaround on this setup.
    Quickshell.execDetached({
      command: [
        "/usr/bin/uwsm-app", "--",
        "env", "WEBKIT_DISABLE_DMABUF_RENDERER=1",
        "/usr/bin/proton-authenticator"
      ]
    })
    close()
  }

  onOpenedChanged: {
    if (opened) {
      searchText = ""
      searchField.text = ""
      selectedIndex = 0
      listFlick.contentY = 0
      nowSec = Date.now() / 1000
      lockError = false
      showSettings = false
      clearSettingsFields()
      passwordField.text = ""
      loadLock()
      refresh()
    } else {
      closeAfterCopy.stop()
      copiedKey = ""
      svc.forget()
      if (lockSet && unlockMinutes === 0) lock()
    }
  }

  Service {
    id: svc
    settings: root.settings
    pluginDir: root.pluginDir
  }

  // One clock for every row while open. The helper only re-runs when the
  // code window runs low (Service.tick).
  Timer {
    interval: 1000
    repeat: true
    running: root.opened
    onTriggered: {
      root.nowSec = Date.now() / 1000
      svc.tick(root.nowSec)
    }
  }

  Timer {
    id: copiedTimer
    interval: 1200
    onTriggered: root.copiedKey = ""
  }

  // Short delay so the copied row flashes before the panel goes.
  Timer {
    id: closeAfterCopy
    interval: 180
    onTriggered: root.close()
  }

  Process {
    id: copyProcess
    running: false
    command: []
    stdinEnabled: false
    onStarted: {
      write(root._pendingCopy)
      root._pendingCopy = ""
      stdinEnabled = false // closes stdin -> EOF, wl-copy takes the data
    }
    onExited: { root._pendingCopy = ""; stdinEnabled = false }
  }

  Timer {
    id: clipboardClearTimer
    interval: Math.max(1, root.clipboardClearSec) * 1000
    onTriggered: root.clearClipboardIfOurs()
  }

  Process {
    id: clipboardCheck
    running: false
    command: []
    stdinEnabled: false
    stdout: StdioCollector {
      id: clipboardCheckOut
      waitForEnd: true
    }
    onStarted: {
      write(root._pendingCheck)
      root._pendingCheck = ""
      stdinEnabled = false
    }
    onExited: {
      root._pendingCheck = ""
      stdinEnabled = false
      var current = root._clipboardCode === root._checkingCode
      if (current && clipboardCheckOut.text === "match\n") {
        clearProcess.command = ["wl-copy", "--clear"]
        clearProcess.running = true
      }
      if (current) root._clipboardCode = ""
      root._checkingCode = ""
    }
  }

  Timer {
    interval: 10000
    running: clipboardCheck.running
    onTriggered: clipboardCheck.running = false
  }

  Process { id: clearProcess; running: false; command: [] }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { root.refresh(); return "ok" }
    function clearClipboard(): string { root.clearClipboardIfOurs(); return "ok" }
  }

  // ---------- Bar icon ----------
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: "Authenticator"
    iconComponent: Component {
      Item {
        ProtonAuthIcon {
          anchors.centerIn: parent
          iconSize: Style.space(12)
          color: root.healthy ? root.barForeground : root.dimForeground
          iconOpacity: root.healthy ? 1.0 : 0.6
        }
      }
    }
    onPressed: function(b) {
      if (b === Qt.RightButton) root.refresh()
      else root.toggle()
    }
  }

  // One account: issuer and account on the left, code and countdown on the
  // right. Same row chrome as the network list (CursorSurface).
  component AccountRow: CursorSurface {
    id: row

    required property var modelData
    required property int index
    readonly property var entry: modelData.entry
    readonly property var st: Model.codeState(entry, root.nowSec)
    readonly property bool ending: st.remaining <= 5

    implicitHeight: rowBody.implicitHeight + Style.spacing.rowPaddingX
    hasCursor: index === root.selectedIndex
    current: root.copiedKey === Model.entryKey(entry)
    foreground: root.barForeground

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton | Qt.RightButton
      cursorShape: Qt.PointingHandCursor
      onContainsMouseChanged: if (containsMouse) root.selectedIndex = row.index
      onClicked: function(mouse) {
        root.selectedIndex = row.index
        if (mouse.button === Qt.RightButton) root.togglePin(row.entry)
        else root.copyCode(row.entry, row.st.code, false)
      }
    }

    Item {
      id: rowBody
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      implicitHeight: Math.max(labels.implicitHeight, codeColumn.implicitHeight)

      Column {
        id: labels
        anchors.left: parent.left
        anchors.right: codeColumn.left
        anchors.rightMargin: Style.space(10)
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(1)

        Text {
          width: parent.width
          // Vault labels are untrusted: never render them as rich text.
          textFormat: Text.PlainText
          text: (row.modelData.pinned ? "󰐃 " : "") + String(row.entry.issuer || "Account")
          color: root.barForeground
          font.family: root.ff
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }

        Text {
          width: parent.width
          visible: text.length > 0
          textFormat: Text.PlainText
          text: String(row.entry.account || "")
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Column {
        id: codeColumn
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(3)

        Text {
          anchors.right: parent.right
          textFormat: Text.PlainText
          text: row.st.stale ? "··· ···" : Model.formatCode(row.st.code)
          color: row.ending ? root.urgent : root.barForeground
          font.family: root.ff
          font.pixelSize: Style.font.subtitle
        }

        // Countdown, drawn like sysmon's core bars.
        Item {
          anchors.right: parent.right
          width: Style.space(52)
          height: Style.space(2)

          Rectangle {
            anchors.fill: parent
            radius: height / 2
            color: root.barForeground
            opacity: 0.06
          }

          Rectangle {
            anchors.right: parent.right
            height: parent.height
            radius: height / 2
            width: parent.width * Math.max(0, Math.min(1, row.st.remaining / row.st.period))
            color: row.ending ? root.urgent : Color.accent
            opacity: 0.85
          }
        }
      }
    }
  }

  // Password input used by the Lock settings: Esc goes back, Enter submits.
  component SettingsField: TextField {
    signal submit()
    width: parent.width
    password: true
    font.family: root.ff
    font.pixelSize: Style.font.body
    foreground: root.barForeground
    onTextChanged: if (text.length) root.settingsMsg = ""

    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Escape) root.closeSettings()
      else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) submit()
      else return
      event.accepted = true
    }
  }

  // ---------- Panel ----------
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: !root.granted ? passwordField
      : root.showSettings ? (root.lockSet ? currentField : newField) : searchField
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(
      !root.granted ? lockColumn.implicitHeight
        : root.showSettings ? settingsColumn.implicitHeight : column.implicitHeight,
      Style.space(560))

    Column {
      id: lockColumn
      visible: !root.granted
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(10)

      PanelSectionHeader {
        text: root.lockReady ? "LOCKED" : "LOADING"
        foreground: root.barForeground
        fontFamily: root.ff
      }

      TextField {
        id: passwordField
        width: parent.width
        password: true
        enabled: root.lockReady && root.lockoutLeft === 0
        placeholderText: "Password"
        font.family: root.ff
        font.pixelSize: Style.font.body
        foreground: root.barForeground
        onTextChanged: if (text.length) root.lockError = false

        Keys.onPressed: function(event) {
          var shift = event.modifiers & Qt.ShiftModifier
          if (event.key === Qt.Key_Escape) {
            root.close()
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            root.tryUnlock()
          } else if (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab) {
            root.switchPanel(shift || event.key === Qt.Key_Backtab ? -1 : 1)
          } else {
            return
          }
          event.accepted = true
        }
      }

      Text {
        width: parent.width
        text: root.lockoutLeft > 0 ? "Too many tries. Wait " + root.lockoutLeft + " s"
          : root.lockError ? "Wrong password"
          : root.unlockMinutes === 0 ? "Locks again when you close the panel"
          : "Unlocks for " + root.unlockMinutes + " minutes"
        color: (root.lockError || root.lockoutLeft > 0) ? root.urgent : root.dimForeground
        font.family: root.ff
        font.pixelSize: Style.font.caption
      }
    }

    Column {
      id: column
      visible: root.granted && !root.showSettings
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(14)

      TextField {
        id: searchField
        width: parent.width
        placeholderText: "Search accounts"
        font.family: root.ff
        font.pixelSize: Style.font.body
        foreground: root.barForeground
        onTextChanged: root.searchText = text

        Keys.onPressed: function(event) {
          var ctrl = event.modifiers & Qt.ControlModifier
          var shift = event.modifiers & Qt.ShiftModifier
          if (event.key === Qt.Key_Escape) {
            root.close()
          } else if (event.key === Qt.Key_Down || (ctrl && event.key === Qt.Key_J)) {
            root.moveCursor(1)
          } else if (event.key === Qt.Key_Up || (ctrl && event.key === Qt.Key_K)) {
            root.moveCursor(-1)
          } else if (event.key === Qt.Key_PageDown) {
            root.moveCursor(5)
          } else if (event.key === Qt.Key_PageUp) {
            root.moveCursor(-5)
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            root.copySelected(!!shift)
          } else if (ctrl && event.key === Qt.Key_P) {
            if (root.selectedRow) root.togglePin(root.selectedRow.entry)
          } else if (ctrl && event.key === Qt.Key_Comma) {
            root.openSettings()
          } else if (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab) {
            root.switchPanel(shift || event.key === Qt.Key_Backtab ? -1 : 1)
          } else {
            return
          }
          event.accepted = true
        }
      }

      PanelSeparator { id: separatorTop; foreground: root.barForeground }

      Column {
        id: listSection
        width: parent.width
        spacing: Style.space(6)

        Item {
          id: listHeader
          width: parent.width
          implicitHeight: sectionTitle.implicitHeight

          PanelSectionHeader {
            id: sectionTitle
            anchors.left: parent.left
            text: root.searchText.length ? "RESULTS" : "ACCOUNTS"
            foreground: root.barForeground
            fontFamily: root.ff
          }

          PanelSectionHeader {
            anchors.right: parent.right
            visible: root.rows.length > 0
            text: String(root.rows.length)
            foreground: root.barForeground
            fontFamily: root.ff
          }
        }

        Text {
          id: statusText
          width: parent.width
          visible: text.length > 0
          text: root.statusLine
          textFormat: Text.PlainText
          color: (!svc.ok && svc.error) ? root.urgent : root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // Only the list scrolls. A Flickable rather than a ListView: the model
        // is rebuilt on every refresh and a ListView would jump to the top.
        Flickable {
          id: listFlick
          width: parent.width
          visible: root.rows.length > 0
          readonly property real maxHeight: {
            var cardCap = panel.availableCardHeight > 0
              ? Math.min(Style.space(560), panel.availableCardHeight) : Style.space(560)
            var fixed = searchField.height + separatorTop.height + separatorA.height + separatorB.height
              + listHeader.height + footer.height + bottomRow.height
              + (statusText.visible ? statusText.height + listSection.spacing : 0)
              + column.spacing * 6 + listSection.spacing
            return Math.max(Style.space(44), cardCap - panel.verticalContentInset - fixed)
          }
          height: visible ? Math.min(listColumn.implicitHeight, maxHeight) : 0
          contentWidth: width
          contentHeight: listColumn.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          interactive: contentHeight > height
          ScrollBar.vertical: ScrollBar { policy: listFlick.interactive ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff }

          Column {
            id: listColumn
            // Room for the scrollbar so it does not cover the codes.
            width: listFlick.width - (listFlick.interactive ? Style.space(10) : 0)
            spacing: Style.space(2)

            Repeater {
              id: entryRepeater
              model: root.rows
              delegate: AccountRow { width: listColumn.width }
            }
          }
        }
      }

      PanelSeparator { id: separatorA; foreground: root.barForeground }

      // Next code for the selected account, and the keys.
      Item {
        id: footer
        width: parent.width
        implicitHeight: Math.max(nextText.implicitHeight, hintText.implicitHeight)

        Text {
          id: nextText
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          textFormat: Text.PlainText
          text: root.selectedState && root.selectedState.next
            ? "󰒭  " + Model.formatCode(root.selectedState.next) : ""
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.caption
        }

        Text {
          id: hintText
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: "↵ copy   ⇧↵ next   ^P pin"
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.caption
        }
      }

      PanelSeparator { id: separatorB; foreground: root.barForeground }

      Row {
        id: bottomRow
        width: parent.width
        spacing: Style.space(6)

        Button {
          id: openButton
          width: parent.width - settingsButton.width - parent.spacing
          iconText: "󰐕"
          iconSize: Style.font.icon
          text: "Add in Proton Authenticator"
          fontSize: Style.font.bodySmall
          foreground: root.barForeground
          fontFamily: root.ff
          horizontalPadding: Style.spacing.controlPaddingX
          verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
          bordered: true
          onClicked: root.openApp()
        }

        Button {
          id: settingsButton
          iconText: root.lockSet ? "󰌾" : "󰌿"
          iconSize: Style.font.icon
          focusable: true
          tooltipText: "Lock settings (Ctrl+,)"
          foreground: root.barForeground
          fontFamily: root.ff
          horizontalPadding: Style.spacing.controlPaddingX
          verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
          bordered: true
          onClicked: root.openSettings()
        }
      }
    }

    // Lock settings: password and how long the panel stays open after unlock.
    Column {
      id: settingsColumn
      visible: root.granted && root.showSettings
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(10)

      PanelSectionHeader {
        text: "LOCK SETTINGS"
        foreground: root.barForeground
        fontFamily: root.ff
      }

      Text {
        width: parent.width
        text: root.lockSet
          ? "Codes are hidden until you enter the password."
          : "No password set. Anyone who opens the panel sees your codes."
        color: root.dimForeground
        font.family: root.ff
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
      }

      SettingsField {
        id: currentField
        visible: root.lockSet
        placeholderText: "Current password"
        KeyNavigation.tab: newField
      }

      SettingsField {
        id: newField
        placeholderText: root.lockSet ? "New password" : "Password"
        KeyNavigation.tab: confirmField
      }

      SettingsField {
        id: confirmField
        placeholderText: "Repeat password"
        onSubmit: root.savePassword(false)
        KeyNavigation.tab: saveButton
      }

      Row {
        width: parent.width
        spacing: Style.space(6)

        Button {
          id: saveButton
          width: root.lockSet ? (parent.width - parent.spacing) / 2 : parent.width
          focusable: true
          text: root.lockSet ? "Change password" : "Set password"
          fontSize: Style.font.bodySmall
          foreground: root.barForeground
          fontFamily: root.ff
          horizontalPadding: Style.spacing.controlPaddingX
          verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
          bordered: true
          onClicked: root.savePassword(false)
        }

        Button {
          id: removeButton
          visible: root.lockSet
          width: (parent.width - parent.spacing) / 2
          focusable: true
          text: "Remove"
          fontSize: Style.font.bodySmall
          foreground: root.barForeground
          fontFamily: root.ff
          horizontalPadding: Style.spacing.controlPaddingX
          verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
          bordered: true
          onClicked: root.savePassword(true)
        }
      }

      Text {
        width: parent.width
        visible: text.length > 0
        text: root.settingsMsg
        color: root.settingsMsgError ? root.urgent : root.dimForeground
        font.family: root.ff
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
      }

      PanelSeparator { foreground: root.barForeground }

      NumberField {
        width: parent.width
        label: "Stay unlocked (minutes, 0 = until closed)"
        value: root.unlockMinutes
        from: 0
        to: 1440
        stepSize: 5
        foreground: root.barForeground
        fontFamily: root.ff
        fontSize: Style.font.bodySmall
        onModified: function(v) { root.saveMinutes(v) }
      }

      PanelSeparator { foreground: root.barForeground }

      Button {
        width: parent.width
        focusable: true
        iconText: "󰁍"
        iconSize: Style.font.icon
        text: "Back"
        fontSize: Style.font.bodySmall
        foreground: root.barForeground
        fontFamily: root.ff
        horizontalPadding: Style.spacing.controlPaddingX
        verticalPadding: Style.spacing.controlPaddingY + Style.space(2)
        bordered: true
        onClicked: root.closeSettings()
      }
    }
  }
}
