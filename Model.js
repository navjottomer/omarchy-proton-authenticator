.pragma library

function parseList(raw) {
  try {
    var data = JSON.parse(String(raw || ""))
    if (!data || typeof data !== "object")
      return { ok: false, entries: [], error: { code: "DECRYPT_FAILED", message: "Invalid JSON" } }
    if (!Array.isArray(data.entries)) data.entries = []
    return data
  } catch (e) {
    return { ok: false, entries: [], error: { code: "DECRYPT_FAILED", message: String(e) } }
  }
}

function formatCode(code) {
  var s = String(code || "").replace(/\s+/g, "")
  if (s.length === 6) return s.slice(0, 3) + " " + s.slice(3)
  if (s.length === 8) return s.slice(0, 4) + " " + s.slice(4)
  return s
}

// Stable key for pins and recent-use. The vault id when there is one, so a
// renamed account keeps its pin.
function entryKey(entry) {
  if (!entry) return ""
  if (entry.id) return "id:" + String(entry.id)
  return "label:" + String(entry.issuer || "") + "|" + String(entry.account || "")
}

// Current code, next code and countdown for `nowSec`, picked from the window
// of codes the helper sent. `stale` means the window has run out.
function codeState(entry, nowSec) {
  var period = Number(entry && entry.period) || 30
  var codes = (entry && entry.codes) || []
  var idx = Math.floor(nowSec / period) - Number(entry && entry.counter || 0)
  var ok = idx >= 0 && idx < codes.length
  return {
    code: ok ? codes[idx] : "",
    next: ok && idx + 1 < codes.length ? codes[idx + 1] : "",
    remaining: period - (Math.floor(nowSec) % period),
    period: period,
    stale: !ok
  }
}

// When to fetch a new window: once any entry is down to its last code.
function refreshAt(entries) {
  var at = Infinity
  for (var i = 0; i < (entries || []).length; i++) {
    var e = entries[i]
    var period = Number(e.period) || 30
    var n = (e.codes || []).length
    if (n === 0) continue
    at = Math.min(at, (Number(e.counter) + n - 1) * period)
  }
  return at
}

// Lower is better; -1 means no match.
function matchScore(entry, q) {
  if (!q) return 0
  var issuer = String(entry.issuer || "").toLowerCase()
  var account = String(entry.account || "").toLowerCase()
  if (issuer.indexOf(q) === 0) return 0
  if ((" " + issuer).indexOf(" " + q) >= 0) return 1
  if (issuer.indexOf(q) >= 0) return 2
  if (account.indexOf(q) >= 0) return 3
  // Letters in order, e.g. "gh" for GitHub.
  var hay = issuer + " " + account, j = 0
  for (var i = 0; i < hay.length && j < q.length; i++) if (hay[i] === q[j]) j++
  return j === q.length ? 4 : -1
}

// Filter by query, then order: match quality, pinned, then sortMode.
function rankEntries(entries, query, pins, used, sortMode) {
  var q = String(query || "").trim().toLowerCase()
  var rows = []
  var list = entries || []
  for (var i = 0; i < list.length; i++) {
    var e = list[i]
    var score = matchScore(e, q)
    if (score < 0) continue
    var key = entryKey(e)
    rows.push({ e: e, score: score, pinned: !!(pins && pins[key]), used: Number(used && used[key]) || 0, vault: i })
  }
  rows.sort(function(a, b) {
    if (a.score !== b.score) return a.score - b.score
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1
    if (sortMode === "recent" && a.used !== b.used) return b.used - a.used
    if (sortMode === "vault") return a.vault - b.vault
    var ai = String(a.e.issuer || "").toLowerCase(), bi = String(b.e.issuer || "").toLowerCase()
    if (ai !== bi) return ai < bi ? -1 : 1
    var aa = String(a.e.account || "").toLowerCase(), ba = String(b.e.account || "").toLowerCase()
    return aa < ba ? -1 : (aa > ba ? 1 : a.vault - b.vault)
  })
  var out = []
  for (var k = 0; k < rows.length; k++) out.push({ entry: rows[k].e, pinned: rows[k].pinned })
  return out
}

// Human-readable status for helper error codes.
function errorHint(error) {
  if (!error) return ""
  var code = String(error.code || "")
  var hints = {
    DEPS_MISSING: "Missing dependency (python-cryptography, python-pyotp, libsecret)",
    VAULT_UNREADABLE: "Open Proton Authenticator once and sign in or add a code",
    KEY_MISSING: "Vault key not in keyring — open Proton Authenticator once",
    KEYRING_LOCKED: "Keyring is locked — unlock it and retry",
    UNSUPPORTED_SCHEMA: "Unsupported Proton Authenticator version",
    HELPER_TIMEOUT: "Timed out reading the vault or keyring — unlock the keyring and retry",
    OUTPUT_TOO_LARGE: "Vault too large to display",
    DECRYPT_FAILED: "Could not decrypt the vault"
  }
  var hint = hints[code] || ""
  var msg = String(error.message || code || "Error")
  return hint ? hint + " (" + code + ")" : msg
}
