# Changelog

## [v32] - 2026-11-22 — Security scan (CodeQL) fixes

Went through all 40 open CodeQL alerts one by one.

### Fixed
- **Integer conversions** (`go/incorrect-integer-conversion`, 12 alerts): values read from the directory (password
  policy, fine-grained policies, GPO flags) are narrowed with a clamped `i32`, and DNS `be16`/`be32` clamp instead of
  wrapping. Same results for real values; out-of-range values no longer wrap around.
- **Logout cookie** now has `Secure` (when served over TLS), `HttpOnly` and `SameSite=Strict`, like the login cookie.
- **Backup folder is confined.** It must be inside `-backup-root` (default `/var/backups`, `ADUC_BACKUP_ROOT`), and the
  create, list, rotate and run steps each re-check that, so a stored or submitted path can't reach elsewhere on disk.
  **Behaviour change from v31:** a folder outside `/var/backups` is refused; the default is now
  `/var/backups/samba-ad` (unchanged). If you saved another folder, move it under the root or set `-backup-root`.
- **Peer purge host** now comes from the directory's own DC list (the matching entry), not from the browser's text.
- **Zip Slip** (updater): the extraction target is also checked to be inside the unpack folder after `badEntry`.
- **GPO file paths** (`gpofiles.go`, ~20 alerts): path components are required to be local (no `..`, separators or NUL)
  where they are resolved, and the final path is checked to be inside the GPO folder. The existing checks (`safeRel`,
  symlink refusal) already prevented escaping; these make the guarantee explicit.

### Not changed (needs dismissing in GitHub as false positives)
- **Disabled TLS certificate check** in `peers.go` (2 alerts). That is deliberate: the probe only reads a peer's
  certificate so you can see its fingerprint and decide to trust it (nothing is sent), and the purge connection checks
  the certificate by hand against the name or the exact fingerprint you approved. Comments in the code say so.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 cross-compiles, `node --check static/*.js`. New `TestBackupDirConfined`; backup tests updated for the root.

### Not verified
- That CodeQL now closes the alerts: it can't be run here. Push and re-scan; any that remain are named by line in the
  new scan.

## [v31] - 2026-11-22 — Settings > Backup: scheduled offline domain backups with FIFO rotation

### Added
- **Settings > Backup** tab. *Back up now* runs `samba-tool domain backup offline --targetdir=<folder>`; *Run
  automatically* does it daily or weekly at a chosen server time. After each successful backup the oldest `*.tar.bz2`
  files in the folder are deleted until *Keep* (1-365) remain. A failed backup removes nothing. The page shows the last
  result (when, file, who/what started it, what was rotated away), the next run, and the files in the folder.
- **Gated like the other local operations:** only a verified Domain/Enterprise Admin (checked over their own LDAP
  connection) can save the schedule or run a backup, and it needs goaduc to run as root with `samba-tool` on the host;
  otherwise the page says why it can't run. Changes and runs are logged.
- Schedule and last result are kept in `backup.json` in the data directory. A slot that passed while the schedule was
  off, or while goaduc was down, doesn't fire retroactively more than once, and one slot never runs twice. The folder
  is created 0700; backups are not offered for download (they contain secrets).
- `snaps/17-settings-backup.png` and a Backup section in the README.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 cross-compiles, `node --check static/*.js`. New tests: schedule slots (daily/weekly), rotation (keeps newest,
  ignores other files and folders), API (refused for a non-admin, input validation, manual runs with rotation, failed
  run keeps files, host that can't run, scheduled run, no double run). The tab was driven in Chromium against the mock
  server with a fake backup command: save, run, rotation to 3 files.

### Not verified
- A real `samba-tool domain backup offline` on a real DC: that it runs from goaduc's service account, how long it takes,
  and that the new file is found by diffing the folder before and after (I assumed it writes a `.tar.bz2` into
  `--targetdir`). Run *Back up now* once and check the folder before relying on the schedule.
- A restore from a backup made this way.

## [v30] - 2026-11-21 — Ctrl/shift-click and multi-delete in DNS records

### Added
- **DNS record list supports ctrl/Cmd-click and shift-click** (range; ctrl+shift adds a range), like the object list.
- **Delete works on the whole selection**: one confirmation, then each record is removed. The right-click menu reads
  "Delete N records" for several; Edit… is available only when exactly one record is selected. If a record is refused,
  the ones before it are already gone, the list reloads and the error is shown.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 cross-compiles, `node --check static/*.js`. In Chromium against the mock server: shift range, ctrl toggle,
  ctrl add, right-click > Delete 2 records, confirmation, and the two records gone from the list.

### Not verified
- Against a real Samba DC.

## [v29] - 2026-11-21 — Shift-click ranges and drag-and-drop moves

### Added
- **Shift-click selects a range** in the list (from the last plain or ctrl click); ctrl+shift-click adds the range to the
  current selection. Ctrl/Cmd-click toggling, Move… and Delete… on a multi-selection already worked and are unchanged.
- **Drag and drop to move.** Drag users, groups, computers, contacts, OUs or containers (one, or the whole selection) onto an
  OU or container in the tree or in the list. The target is outlined while you hover, and a Move confirmation appears before
  anything changes. Dropping where the objects already are, onto one of them, or into another naming context is ignored.

### Changed
- Move now shares one routine (`doMove`) between the Move… dialog and drag-and-drop. If one object in a batch is refused,
  the ones before it have already moved; the list and tree are refreshed and the error is shown.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 cross-compiles, `node --check static/*.js`. In Chromium against the mock server: shift range, ctrl toggle,
  ctrl+shift, dragging a group onto an OU, confirmation, and the object appearing in the new OU.

### Not verified
- Dragging several objects at once, and touch screens (HTML5 drag events don't fire on most touch browsers; use Move…).

## [v28] - 2026-11-21 — Create DNS subzones from the zone right-click menu

### Added
- **Right-click a zone > New subzone…** asks for a name and creates `<name>.<zone>` as a primary zone in the same DNS
  partition as the parent (SOA and NS at the apex, secure dynamic updates), then selects it. Reverse zones work the same way.
  The zone is written to the directory as the signed-in user (`POST /api/dns/zonecreate`), not through the DNS RPC
  interface that `samba-tool dns zonecreate` uses. Names are checked, and an existing zone is refused.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 cross-compiles, `node --check static/*.js`. New `TestDNSZoneCreate`; menu, dialog and nested result checked in
  Chromium against the mock server.

### Not verified
- Against a real Samba DC: whether the DNS server serves a zone added this way without a restart, and the dNSProperty
  values (primary, secure updates) are written from the MS-DNSP layout, not compared with one made by samba-tool.
- There is still no zone delete in the UI (`samba-tool dns zonedelete`).

## [v27] - 2026-11-21 — DNS zone list: nested subzones, no pills, no hint text

### Changed
- **`_msdcs` is shown under its parent zone.** Any zone whose name ends in `.<another zone>` is listed beneath that zone,
  indented and labelled with the short name (`ad.example.com` > `_msdcs`). Reverse zones are unaffected.
- **Removed the Forest/Domain scope pills** next to zone names.
- **Removed the "Create or delete zones with samba-tool…" text** under the zone list.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 cross-compiles, `node --check static/*.js`. Zone tree checked in Chromium against the mock server (the mock
  has no forest zone, so the zone list response was stubbed with `_msdcs` and its parent); snaps 05 and 06 retaken.

### Not verified
- Against a real Samba DC's zone list.

## [v26] - 2026-11-21 — Tree rows stay aligned in a narrow pane

### Fixed
- **Tree rows misaligned when the pane was dragged narrow.** The expand arrow (`.twisty`) was a shrinkable flex item, so on rows
  whose name was wider than the pane it was squeezed narrower than on short rows, shifting the icon and text left. The arrow
  no longer shrinks and a row is at least as wide as its content (the pane scrolls sideways instead), so the selection
  highlight also covers the whole name.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 builds and `node --check` on the JS. Chromium against the mock with the pane dragged to its 120 px minimum: arrow
  position and width and icon position identical on every row (before: they differed between short and long names).

### Not verified
- Other browsers (only Chromium was tried).

## [v25] - 2026-11-21 — Recycle Bin: purge on all DCs, with consent; "Deleted from" fix

### Added
- **Purging on the other domain controllers.** A local purge (`ldbdel` / `samba-tool domain tombstones expunge`) is not
  replicated, which is why two DCs showed different bins. When a DC refuses the LDAP purge and the local fallback is
  possible, the page no longer runs it silently: *Delete…* / *Empty Recycle Bin…* now open a dialog ("not replicated") that
  also lists the other DCs. For each ticked DC goaduc signs in on that DC's goaduc as the signed-in user and repeats the
  purge there with `local=true`; the peer checks that user's rights itself. Failures per DC are shown in red
  (`dc2: …`); what this DC did stands. A DC without goaduc shows "not reachable".
- **Self-signed certificates for those calls:** a peer is trusted if its certificate verifies for the DC's name, otherwise
  by an approved SHA-256 fingerprint. The dialog shows the fingerprint of a *new* certificate and the checkbox is the
  approval; approved fingerprints are pinned in `peers.json` (0600, data directory); a different certificate later is
  *changed*, unticked and flagged in red. Nothing (no password) is sent unless the check passes. Peers are taken from the
  directory's DC list only (the request cannot name an arbitrary host), contacted on this goaduc's own port over HTTPS,
  redirects are not followed.
- The Recycle Bin page shows the short name of the DC it is reading.
- `peers.go`, `peers_test.go` (`TestPurgeOnOtherDCs`: consent step, untrusted/wrong/changed certificate sends no login, a
  non-DC host is never contacted, approved purge signs in as the user with `local` and `all`, pin remembered, peer error and
  unreachable peer); the mock server can be started with `ADUC_MOCK_PEERS=1` to try the dialog.

### Changed
- `POST /api/deleted/purge`: without `local:true` a refused purge returns `{needsLocal, server, peers[]}` and does nothing;
  `local` and `peers` carry the person's agreement. `domainControllers()` is shared with the Domain page.

### Fixed
- **"Deleted from" showed a raw `…\0ADEL:<guid>,CN=Deleted Objects,…` path** for objects whose parent was deleted too (a
  GPO's Machine and User folders). It now shows the parent's own name with "(deleted)".

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 builds and `node --check` on the JS. Chromium against the mock with a fake second DC: the dialog, the new
  certificate and its fingerprint (unticked by default), ticking it, both DCs purged, no error text.

### Not verified
- Two real goaduc instances on two Samba DCs, and a real Samba refusing the purge. A peer on an older goaduc (before v25) would
  purge locally without being asked to, because it does not know `local`.

## [v24] - 2026-11-21 — Draggable pane divider; naming contexts under the domain node

### Added
- **The divider between the left and right panes can be dragged** on every two-pane page: the tree in Users and Computers and
  Sites and Services, and the left lists on DNS, Group Policy and Reports. Drag to resize (120 px minimum, always leaving 200 px
  for the right side), double-click to reset to the default; the width is remembered per page in the browser
  (`aduc.pane.<page>` in localStorage; without storage it just does not persist). Replaces the small native resize grip
  the tree had in its bottom corner. Hover/drag shows the divider in the accent colour.

### Changed
- **The other naming contexts are now children of the domain node**, sorted in with Builtin, Computers, Users and the
  rest (Configuration, DomainDnsZones, ForestDnsZones; Schema stays inside Configuration), instead of separate roots below
  the tree. They also appear in the right-hand list when the domain is selected, and open on double-click.
  (Supersedes v22's separate roots and v23's short names.)

### Fixed
- `snaps/10-other-naming-contexts.png` in v23 was the old screenshot (the retake script still looked for the full-DN root
  name); retaken, it now shows the short root names.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 builds and `node --check` on the JS. Chromium against the mock: the domain node's children in the tree and list
  (Configuration, DomainDnsZones, Staff, System, Users, in order), expanding Configuration, double-click from the list; drag wider (290 → 480), clamp at 120 when dragged
  past the edge, width restored after leaving and returning to the page, double-click back to 290, and the same on DNS and
  Group Policy; no page errors. Not tried in dark mode or on a touch screen.

## [v23] - 2026-11-21 — Tidier tree roots for the other naming contexts

### Changed
- The extra roots below the domain in Users and Computers show short names (*Configuration*, *DomainDnsZones*,
  *ForestDnsZones*) instead of full DNs that were cut off at the pane edge; the full DN is the tooltip. They are set apart
  from the domain tree by a small gap.
- The Schema partition is no longer a root of its own: it lives inside Configuration (`CN=Schema,CN=Configuration,…`) and
  was listed twice. It is still reached under Configuration, and *Schema search* still searches it.
- `snaps/10-other-naming-contexts.png` retaken.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 builds and `node --check` on the JS; Chromium against the mock (dark theme): roots *Configuration* and
  *DomainDnsZones*, selecting one lists its children.

### Not verified
- A real Samba DC (it also has *ForestDnsZones*; the mock does not).

## [v22] - 2026-11-21 — LDAP Browser merged into Users and Computers

### Changed
- **The LDAP Browser tab is gone.** Everything it did now lives in Users and Computers: the tree has the domain's other
  naming contexts (Configuration, Schema, DomainDnsZones, …) as extra roots below the domain; their objects show the raw
  LDAP class, open the same properties dialog and have Properties / Open in tree / Refresh / Rename / Delete in the
  right-click menu (not for the naming-context root itself). The find box searches below the selected object with any LDAP
  filter or text when one of those is selected, and *Queries ▾ → Schema search* searches classes and attributes by the
  find box text. Containers in those contexts open on double-click like in the domain (the old browser always opened
  properties). `snaps/10-ldap-browser.png` replaced by `snaps/10-other-naming-contexts.png`; README updated.

### Fixed
- **The sign-in response lacked the naming contexts, schema and root DN** (they only arrived after a page reload through
  `/api/info`), so the old browser's dropdown listed only the domain and schema search used the wrong base right after
  signing in. `POST /api/login` now returns `ncs`, `schema` and `root`; the mock test setup asserts it.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 builds and `node --check` on the JS. In Chromium against the mock: three roots in the tree, expanding
  Configuration, the raw-class column, double-click, right-click menu, Schema search.

### Not verified
- Schema search against real schema data (the mock directory has no schema classes, so it returned 0 objects), and a
  real Samba DC.

## [v21] - 2026-11-21 — Go sources moved into `source/`

### Changed
- **Layout:** `go.mod`, every `*.go`, `VERSION` and `static/` moved into `source/`. (`static/` had to come along: `go:embed`
  cannot read files outside the module directory.) The top of the tree now holds `source/`, `snaps/`, `README.md`,
  `CHANGELOG.md`, `LICENSE`, `install.sh`, `uninstall.sh`, `get.sh` and `CLAUDE.md`. Go commands run from `source/`
  (`cd source && go build -o goaduc .`).
- `install.sh` builds from and checks `source/` (`go.mod`, `main.go`, `VERSION`) and installs `source/VERSION`.
- `get.sh` reads `VERSION` from `source/` and still accepts the old flat layout.
- The in-app updater (`update.go`) finds the module in `source/` and still accepts the flat layout; `go build` runs there.
  `update_test.go` covers both layouts.
- `CLAUDE.md` layout, command locations and packaging notes; README build/test notes.

### Verified
- From `source/`: gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386,
  riscv64 builds and `node --check` on the JS. Installer: `--dry-run`, then a real run in a scratch root with a stub
  `systemctl`: fresh install (`goaduc v20`) and an upgrade from a copied tree with `source/VERSION` bumped (`goaduc v21`,
  installed VERSION updated). `get.sh` against a local fake release (`--version v99`) installed `goaduc v99`.

### Not verified
- Forced-failure rollback, downgrade refusal, distro matrix and uninstall were not re-run: nothing in those paths changed.

### Note for upgrading
- A goaduc **older than v21 cannot update itself to this release from the web UI** (its updater wants `go.mod` at the top
  of the archive). Update once with `install.sh` or the `get.sh` one-liner; from v21 on the Update page works as before.

## [v20] - 2026-11-21 — Settings page: Certificate and Update

### Added
- **Settings** tab (replaces the *Update* tab, last in the row) with two sub-tabs. *Update* is the existing updater,
  unchanged, now at Settings → Update.
- **Settings → Certificate: upload your own web certificate.** *Upload certificate…* takes a PEM certificate (chain
  allowed) and a PEM private key (one combined PEM file also works), checks that they match, that the key has no
  passphrase, that the certificate is valid now and has a DNS/IP name, and swaps it in live through
  `tls.Config.GetCertificate` (no restart; existing connections keep the old one). The page shows source, subject, issuer,
  names, validity, days left (red under 30) and SHA-256. *Use self-signed* goes back to the generated pair.
  Files: `custom.crt` / `custom.key` in `<data dir>/tls` (0644 / 0600), preferred at startup if they load, otherwise
  goaduc falls back to the self-signed pair. Only Domain/Enterprise Admins may change it. With `-tls-cert`/`-tls-key`
  the page is read-only (those files are the operator's), with `-http` there is no certificate. API:
  `GET /api/settings/cert`, `POST /api/settings/cert/save`, `POST /api/settings/cert/reset`. The audit log redacts the
  `key` field.
- `webcert.go`, `webcert_test.go` (`TestWebCertSettings`: mismatch, no key, passphrase key, expired, no names, swap,
  restart picks the upload, reset, a live TLS handshake before/after the swap, non-admin, flag mode, plain HTTP, no private key in the audit log). The mock server
  (`TestMockServe`) now makes `administrator` a Domain Admin so both Settings tabs can be tried.

### Changed
- `main()` serves with `GetCertificate`; `ensureCert` and the self-signed generation are unchanged.
- README: new Settings section (Certificate, Update) with screenshots `14-settings-upload`, `14-settings-certificate`,
  `15-settings-update`; the dark-theme shot is now `16-dark-theme.png`; `snaps/14-update.png` is gone.

### Verified
- gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386, riscv64 builds and
  `node --check` on the JS. In Chromium against the mock: upload of an `openssl req -x509` pair (RSA, two SANs), the
  page updating, switching to the Update tab and back, *Use self-signed*.

### Not verified
- A real Samba DC, and a browser on goaduc's own listener (`TestWebCertLiveSwap` does a real TLS handshake before and after
  a swap on a test listener that uses the same `GetCertificate`).

## [v19] - 2026-11-21 — UPN suffixes: right-click Add/Delete; single-label suffixes

### Changed
- The *Alternative UPN suffixes* card no longer has a Remove button on every row, nor the inline input and Add button.
  Right-click the card for *Add…* (a small dialog; a refused suffix is shown in the dialog), or a suffix for *Add…* /
  *Delete…* (asks first). `snaps/08-domain.png` retaken with the menu open.

### Fixed
- **A single-label suffix such as `local` was refused** (“"local" is not a valid UPN suffix”). AD allows them, so the check
  now accepts one or more DNS-style labels. Still refused: spaces, leading/trailing hyphens, empty, the domain's own name.
  `TestUPNSuffixes` updated.

### Verified
- gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386, riscv64 builds and
  `node --check` on the JS. In Chromium against the mock (dark and light): add via the card menu, refusal inside the
  dialog, add `local`, delete via the row menu.

### Not verified
- A real Samba DC (see v17).

## [v18] - 2026-11-21 — Sign in with the logon name (sAMAccountName)

### Added
- A bare logon name now works on the sign-in page. It is bound as typed first (Samba usually accepts it); on an
  invalid-credentials answer goaduc reads the domain from the DC's anonymous RootDSE and retries once as `name@domain`.
  Names containing `@`, `\` or `=` (UPN, `DOMAIN\user`, DN) are sent as typed with no retry, so a wrong password still
  fails the same way. The session keeps whichever form worked. `TestLoginWithSamAccountName` (the mock can now be set to
  refuse bare-name binds). Sign-in forms are described in the README.

### Verified
- gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386, riscv64 builds and
  `node --check` on the JS.

### Not verified
- A real Samba DC: whether it takes a bare sAMAccountName in a simple bind (the retry covers it if not), and
  that the retry cannot lock accounts faster (a wrong password now costs two failed binds, which counts twice toward
  the lockout threshold).

## [v17] - 2026-11-21 — Alternative UPN suffixes

### Added
- **Alternative UPN suffixes.** New *Alternative UPN suffixes* card on the Domain page: list, add (Enter or *Add*) and
  remove. They are stored in `uPNSuffixes` on `CN=Partitions,<configuration>` (what Active Directory Domains and Trusts
  edits), through new `GET`/`PUT /api/upnsuffixes`, run as the signed-in user so AD's ACLs decide. Input is lowercased,
  a leading `@` is dropped, duplicates are ignored, anything that is not a DNS-style name (or is the domain's own name)
  is refused. When any suffix exists, the New User dialog and the user's Account tab get a *UPN suffix* drop-down that
  rewrites the part after `@` of the UPN field; without suffixes nothing changes in those dialogs.
- `TestUPNSuffixes` (read, normalise/dedupe, refusals, clear).

### Changed
- `README.md` Domain section describes it; `snaps/08-domain.png` retaken to show the new card.

### Verified
- gofmt, `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, linux/amd64, arm64, arm, 386, riscv64 builds and
  `node --check` on every static JS file. In Chromium against the mock directory: adding, rejecting (red text beside
  the button) and removing suffixes, the drop-down in New User (`zoe` + `example.org` → `zoe@example.org`) and on the
  Account tab, light and dark themes.

### Not verified
- A real Samba DC: whether it lets the signed-in account write `uPNSuffixes` (it does for Enterprise Admins in AD), and
  how the mock's plain attribute replace compares to Samba's schema checks.

## [v16] - 2026-11-21 — Screenshots in `snaps/`; README rewritten; lighter dark theme

### Added
- `snaps/`: 15 PNG screenshots of the UI (sign-in, Users and Computers, user properties, Sites and Services, DNS and its
  right-click menu, Group Policy, Domain, Reports, LDAP Browser, Audit Log, Recycle Bin and its right-click menu, Update,
  dark theme), embedded in the README with relative links. Taken with Playwright/Chromium at 1280x760 against the mock
  directory (`ADUC_MOCK_SERVE=1 go test -run TestMockServe`), so the names are made up.

### Changed
- **Dark theme lightened about four shades** (`static/style.css`, both the auto and the forced-dark blocks): background
  `#14171b`→`#2b3036`, panels `#1c2026`→`#343a42`, borders `#343a42`→`#4b535d`, selection `#243a5c`→`#34507a`, hover
  `#232a33`→`#3b4450`. Text and accent colours unchanged; checked in a dark-scheme screenshot.
- `README.md` rewritten in plain, first-person prose, one section per page with its screenshot. The facts (install
  commands and options, flags/env, updater rules, Recycle Bin and fallbacks, SYSVOL notes) are carried over unchanged.
- `CLAUDE.md` layout note mentions `snaps/`. No Go or UI code changed.

### Verified
- Every `snaps/*.png` linked in the README exists and was viewed; gofmt, build, vet, `go test -race`, `CGO_ENABLED=0 go test`,
  `go vet`, `go test -race ./...`, `CGO_ENABLED=0 go test ./...`, cross-compiles for linux/amd64, arm64, arm, 386 and riscv64, and
  `node --check` on every static JS file all passed.

### Not verified
- Screenshots are from the mock directory, not a real Samba DC.

## [v15] - 2026-11-21 — Deleted DNS records and subnets show in the Recycle Bin; tab order

### Fixed
- **Deleted subnets (and sites, site links, other Configuration objects) were missing from the Recycle Bin page.** Each
  partition has its own Deleted Objects; Configuration objects go to `CN=Deleted Objects,CN=Configuration,…`, and the page
  only searched the domain's. It now searches both (a refusal from the Configuration search does not hide the domain's list).
  Restore and Delete/Empty already worked on those DNs. The mock now keeps the two partitions apart (a domain search
  does not reach Configuration, and Configuration deletes go to their own container), and
  `TestConfigurationDeletesGoToTheBin` fails without the fix.
- **Deleted DNS records did not go to the Recycle Bin**, and could not: a record is a value of the `dnsRecord` attribute of a
  DNS node, so deleting one is an attribute change that AD never keeps. goaduc now keeps its own list of the records deleted
  on the DNS page (`dns-recycle.json` in the data directory, 0600, newest 2000), and the Recycle Bin page lists them as
  *DNS record* (name, type, data, zone, time). Right-click: *Restore…* adds the record back through the same path as *New
  record…* (AD's ACLs and the CNAME rule apply; a refused restore keeps the entry), *Delete…* and *Empty Recycle Bin…* remove
  entries. Removing entries is not an LDAP operation, so it is limited to Domain and Enterprise Admins (everyone may restore
  with their own DNS rights). Only records deleted through goaduc are in it; records deleted by `samba-tool` or DNS Manager
  are not. A restored record is static (it loses its aging timestamp) and gets a fresh serial.
- The empty DNS node that is deleted along with a name's last record no longer shows up on the page as a junk "deleted
  object" (nodes with no `dnsRecord` value are skipped; nodes that still hold records are listed as before).

### Changed
- The Recycle Bin tab now sits just before Update (order: … Reports, LDAP Browser, Audit Log, Recycle Bin, Update).
- New routes `POST /api/deleted/dns/restore`; `GET /api/deleted` carries a `dns` list; `POST /api/deleted/purge` also takes
  `{dns: id}` and `{all: true}` empties the DNS list too.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.
- `TestDNSRecycleBin`: A, MX, SRV, TXT and CNAME records deleted and restored with the same type, data and TTL; the list
  survives a reload from the data directory; a restore that violates the CNAME rule leaves the entry; non-admins cannot
  remove entries, a Domain Admin can; Empty takes AD objects and DNS entries together.
- Mock UI in headless Chromium (tab order checked too): deleting a CNAME on the DNS page, it appears on the Recycle Bin page as a *DNS record*
  with the zone, right-click offers Restore, Delete and Empty, Restore puts it back on the DNS page.

### Not verified
- Not against a real DC: that a deleted subnet really sits in the Configuration partition's Deleted Objects and is
  listable by that search on Samba (it is on AD), and that restoring one works there (the restore is a modify of
  `distinguishedName` with the show-deleted control, as for domain objects).

## [v14] - 2026-11-21 — Update page and get.sh; Recycle Bin purge falls back to the local tools

### Added
- **Update page** (new top-bar tab). *Check online* asks GitHub for the newest release of `-update-repo`
  (`ADUC_UPDATE_REPO`, default `micush/goaduc`), *Update to vN* installs it, *Upload release…* installs a
  `goaduc_vN.tgz`. The release is unpacked, built on this host (`go build`, CGO off, `GOTOOLCHAIN=local`, `GOPROXY=off`),
  the built binary must report the new version, then the old binary is saved as `goaduc.prev` (the installer's file, in
  `<bin dir>/../share/goaduc` when that exists, otherwise beside the binary), the new one is swapped in and goaduc
  re-executes itself (same PID, so systemd sees nothing; sessions are lost, so everyone signs in again). A boot guard
  (`<data dir>/update/state.json`) counts starts of the new version: one that stays up 60 s is accepted, one that fails
  to start three times is replaced by the saved binary automatically. State words are in the buttons ("Building…",
  "Restarting…"); a failure is red text in the toolbar; the last update is one line in the page.
  - Only **Domain Admins and Enterprise Admins** (in-chain membership checked over the signed-in user's own LDAP
    connection) may update; everyone else sees disabled buttons with the reason as the tooltip. `-no-update`
    (`ADUC_NO_UPDATE=1`) turns it off for everyone.
  - Only a strictly newer integer `VERSION` is accepted. The archive is unpacked by a checker that refuses `..`,
    absolute and backslash names, links, devices, more than 2000 files, files over 16 MiB or 64 MiB in all; uploads and
    downloads are capped at 32 MiB; tags are plain characters only. Never skips TLS verification.
  - New routes `GET /api/update`, `POST /api/update/check`, `/online`, `/upload` (raw body; a new `authStream` wrapper
    keeps the archive out of the audit detail and the 1 MiB body buffer; audited by path and user).
- **get.sh**, the web installer from logdir: `curl -fsSL …/get.sh | sudo bash -s -- <install.sh options>` downloads the
  newest GitHub release (or `--version vN`) and runs its `install.sh`, so install and upgrade need no copy of the tree.
  Runs nothing if the download is cut off; accepts a project at the top of the repository or in a `goaduc/` folder;
  test hooks `GOADUC_GET_REPO/API/HOST`.
- **Recycle Bin purge fallback.** When the DC refuses to remove an object from Deleted Objects over LDAP (AD does), and
  goaduc runs as root with `-sam-db` present, and the signed-in user is a verified Domain or Enterprise Admin, *Delete…*
  runs `ldbdel -H <sam.ldb> --controls=show_deleted:1 <dn>` and *Empty Recycle Bin…* runs `samba-tool domain tombstones
  expunge --tombstone-lifetime=0 -H <sam.ldb>`; logged like the Recycle Bin enable fallback. Without those conditions the
  DC's refusal is shown, with what is missing. An expunge that leaves objects behind is reported, not called success.
- The installer's `goaduc.conf` has commented `ADUC_NO_UPDATE` / `ADUC_UPDATE_REPO` lines; `--no-keep-go` help says the
  Update page needs the kept toolchain.

### Changed
- `CLAUDE.md`: file list (`update.go`, `update_test.go`, `get.sh`), a checklist item for the updater, and the new local
  fallback named in the fallback rule and the invariants.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.
- Tests (`update_test.go`, `TestPurgeLocalFallback`): unsafe archives refused (`..`, absolute, symlink, hardlink, device,
  backslash, not gzip, no go.mod) and good ones accepted flat, in `goaduc/` and in `goaduc-vN/`; version rules (same, older,
  semver, zero-padded, empty, missing files); a real `go build` of a small release and the swap; every refusal leaves the
  binary and state untouched; boot-guard transitions including rollback and "no saved binary"; latest-tag lookup (release,
  then tags); the admin gate through the mock (a non-admin is refused for check, online and upload, a Domain Admin is
  not, `-no-update` refuses even an admin); the purge fallback only runs after a refusal, as root, for an admin, and
  reports a failing tool.
- **End to end with the real binary** (built `goaduc` served over the mock LDAP, a restart loop standing in for systemd):
  uploaded a v14 archive → built in about 18 s → re-exec → v14 serving, `goaduc.prev` is v13, state `applying`, then
  `ok` after 60 s; uploaded a v15 whose `main` exits at boot → three failed starts → v14 restored automatically, state
  `rolled-back`, v14 serving again.
- `get.sh` against a fake GitHub: newest release, `--version`, `--version=`, tags fallback, project in a `goaduc/`
  folder, arguments passed to `install.sh`, piped from stdin; bad tag, bad `VERSION`, not a goaduc archive and a missing
  tag are refused; a truncated script runs nothing; no temporary directory left behind.
- `install.sh`: `bash -n`; `--dry-run` for ubuntu, debian, linuxmint, fedora, rocky, almalinux, centos, arch, manjaro,
  endeavouros (alpine refused); a real run under a scratch root with a shim `systemctl`: fresh install, upgrade to a higher
  `VERSION` keeping a hand-added config line, `goaduc.prev` saved, new comment lines written.
- Update page in headless Chromium, light and dark, with the API answers faked for each state: non-admin (disabled, reason
  as tooltip), admin idle, newer found, building, failed, restarting.

### Not verified
- Not under real systemd (re-exec of the service, `Restart=on-failure` counting boot failures) and not on a real Samba
  DC. The restart loop above approximates systemd; a unit that limits restarts (`StartLimitBurst`) could stop retrying
  before the third failed start, in which case the rollback waits for the next manual start.
- Not fetched from real GitHub (a local fake was used), so the default repo name `micush/goaduc` is a guess at where the
  releases live; set `-update-repo` if it differs.
- Not verified on a real Samba DC: whether `ldbdel --controls=show_deleted:1` can remove one object from Deleted
  Objects, and whether `samba-tool domain tombstones expunge --tombstone-lifetime=0` takes `0` as "everything". If either
  fails the tool's message is shown and nothing else changes. `shellcheck` is not installed here (`bash -n` only).
- The full installer battery (every family with a real run, `--run-as` variants, rollback, uninstall/`--purge`) was not
  repeated: the installer change is a help line and commented config lines, checked as above.

## [v13] - 2026-11-21 — Right-click menus on DNS and Group Policy; Recycle Bin delete and empty

### Added
- **DNS:** right-click a record (*Edit…*, *Delete*, *New record…*, *Refresh*), the empty part of the list (*New record…*,
  *Refresh*) or a zone (*New record…*, *Refresh*).
- **Group Policy:** right-click a GPO in the list (*New GPO…*, *Rename…*, *Delete*, *Refresh*); a link on the Links tab
  (*Move up*, *Move down*, *Unlink*, *Add link…*); an entry on the Computer, User and Security tabs (*Edit…*, *Remove*,
  *Add…*); a file or folder on the Files tab (*Open*, *Download*, *Delete*, *New file…*, *New folder…*, *Upload…*); and
  the empty part of each of those tabs for the *Add* entries. Entries that cannot apply (read-only SYSVOL, a directory
  download) are greyed.
- **Recycle Bin:** right-click an object for *Restore…*, *Delete…* (removes it from the bin for good) or *Empty Recycle
  Bin…* (removes all); right-click the empty part of the page for *Empty Recycle Bin…*. New `POST /api/deleted/purge`
  (`{dn}` for one object, `{all:true}` for everything): a plain LDAP delete with the show-deleted control, run as the
  signed-in user and audited; the DN must be inside Deleted Objects. With *all*, objects that fail are skipped and the
  count is reported ("N of M removed: …") as red text in the page toolbar.

### Changed
- The Recycle Bin page no longer has a *Restore…* button on every row; restore is in the right-click menu.
- Mock DC: deleting an object that is already in Deleted Objects removes it. `TestPurgeRecycleBin` covers one, all, the
  refusals (not in Deleted Objects, another domain) and that the rest of the directory is untouched.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.
- Mock UI in headless Chromium, light and dark: every menu above shows the expected entries (Registry.pol and Security
  rows not exercised: the mock GPO has none); on the Recycle Bin page, deleting one object and emptying the bin work and
  the page's empty-state menu greys *Empty*.

### Not verified
- Not run against a real DC. Whether Samba (or AD) lets an LDAP client remove an object from Deleted Objects is not
  confirmed: AD answers unwilling-to-perform, and removal normally happens by garbage collection after the tombstone
  lifetime. If your DC refuses, the page shows its error and nothing changes; a local `samba-tool domain tombstones
  expunge` fallback (root, like the Recycle Bin enable fallback) is the likely next step.
- The existing row-click redraw on the DNS and Group Policy tables (not the ADUC list) was left as it is.

## [v12] - 2026-11-21 — Properties dialog: no Apply button

### Changed
- The Properties dialog (users, groups, computers, OUs, Sites and Services objects) has only *Cancel* and *OK* now;
  *Apply* is removed. *OK* saves every edited tab and closes; a failed save keeps the dialog open with the error in
  red beside the buttons, as before.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.
- Mock UI in headless Chromium, light and dark: footer shows Cancel and OK only; editing a group's description and
  pressing OK saves it, closes the dialog and the list shows the new value.

### Not verified
- The failed-save path (error text, dialog stays open) was not exercised in the browser; that code is unchanged.

## [v11] - 2026-11-21 — Delete says whether it goes to the Recycle Bin

### Fixed
- The Delete dialog always said "Permanently delete … cannot be undone", even with the Recycle Bin on. It now asks the
  directory (new `GET /api/recyclebin`: `enabled`, `known`) and says "It goes to the Recycle Bin." when the feature is
  on, or "The Recycle Bin is off; this cannot be undone." when it is off or could not be read.

### Added
- `GET /api/recyclebin` (status only, runs as the signed-in user).
- Mock DC: with the Recycle Bin feature on, a delete in the domain keeps the object in Deleted Objects (as a real DC
  does). `TestDeleteGoesToRecycleBin` deletes through `/api/delete`, finds the object in `/api/deleted`, restores it,
  then switches the feature off and checks a delete is final.

### Not changed
- `/api/delete` is still a plain LDAP delete (tree-delete control only with the subtree option). Whether the object is
  recycled is decided by the domain controller: with the Recycle Bin off (the default on Windows and on a fresh Samba
  domain) a delete leaves only a tombstone, and the app cannot keep a copy. Enabling it stays a separate, deliberate
  action on the Recycle Bin page, because it is forest-wide and irreversible.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.
- Mock UI in headless Chromium: dialog text with the feature on and off (`ADUC_MOCK_RB=off`); a user deleted with it on
  appears on the Recycle Bin page with *Restore…*.

### Not verified
- Not run against a real Samba DC: that Samba recycles a plain delete (and a tree delete) once the feature is on, and
  what your domain's feature state is. If objects still vanish with the dialog saying "goes to the Recycle Bin", that
  is a DC-side problem the mock cannot show.

## [v10] - 2026-11-21 — Double-click in the object list opens properties reliably

### Fixed
- Double-clicking an object in the right-hand list (Users and Computers, Sites and Services, LDAP Browser, search
  results) could do nothing. The first click of the double-click rebuilt every row of the table to show the
  selection, so the second click landed on a brand-new row and some browsers never delivered the `dblclick`. Selection
  (click, Ctrl/Cmd-click, right-click) now only toggles the `sel` class on the existing rows, and double-click is handled
  once on the list itself, so it no longer depends on which row element was clicked.
- Double-click also selects the row it opens.

### Unchanged
- Double-clicking a container (OU, container, and in Sites and Services a site, servers container, server, NTDS
  Settings, transport) still opens it in the tree; everything else opens Properties.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.
- Against the mock (`TestMockServe`) in headless Chromium, light and dark: a row element survives a click, Ctrl-click
  multi-selects, right-click selects and opens the menu, a real-mouse double-click (250 ms apart) on a user opens its
  Properties dialog, and double-clicking every object in an OU opens each one without console errors.

### Not verified
- Only Chromium is installed in the sandbox. The failure was not reproducible there (it opened properties before the
  change too), so the fix targets the row rebuild on click and was not seen in Firefox or Safari.

## [v9] - 2026-11-10 — Rename to "Directory Manager"

### Changed
- Sign-in page title and browser tab title are now "Directory Manager" (was "Active Directory Management" in v8).

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.

### Not verified
- Not viewed in a browser.

## [v8] - 2026-11-10 — Sign-in page wording

### Changed
- Sign-in page and browser tab title are now "Active Directory Management"; the "Sign in with a domain account…" line is removed.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles (amd64, arm64, arm, 386, riscv64), `node --check` on the scripts.

### Not verified
- Not viewed in a browser.


## [v7] - 2026-11-10 — Enable Recycle Bin works on Samba

### Fixed
- *Enable Recycle Bin…* failed on Samba with "rootdse: Insufficient rights for enableoptionalfeature" even for an
  Enterprise Admin, because Samba only accepts that rootDSE request from its local system context.

### Added
- Local fallback: when that request is refused (LDAP 50/53), goaduc is root, `sam.ldb` exists and the signed-in user is
  confirmed (over their own connection) to be in Enterprise Admins, it applies the same change with `ldbmodify` on
  `-sam-db` / `ADUC_SAMDB` (default `/var/lib/samba/private/sam.ldb`; needs `ldb-tools`) and logs it. Otherwise the
  original error is shown, with a reason.
- Tests: fallback not used without root/database, refused for non-Enterprise-Admins, failure leaves nothing changed, success
  enables once.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `CGO_ENABLED=0` vet/test, cross-compiles
  (amd64, arm64, arm, 386, riscv64), `node --check`.

### Not verified
- Against a real Samba DC: the `ldbmodify` invocation and that Samba accepts it this way (it is the documented local
  method, but the code only ran against a stub). If it fails, the error includes ldbmodify's output.


## [v6] - 2026-11-10 — Group Policy: GPOs, links and settings editing

### Added
- **Group Policy** page (top navigation), GPMC-style:
  - GPOs and links, in LDAP as the signed-in user: list (with link count, status, versions), create, rename, delete
    (removes its links everywhere and its SYSVOL folder; the two built-in GPOs can't be deleted), enable/disable the
    computer or user half, link to the domain, an OU or a site with enforced / link enabled, link order (up/down), and
    block inheritance. New links get the lowest precedence. Links are the `gPLink` attribute (the last entry is link
    order 1); options 1 = disabled, 2 = enforced; block inheritance is `gPOptions` bit 1.
  - Settings, in SYSVOL: **Computer** and **User** tabs edit `Registry.pol` (REG_SZ, EXPAND_SZ, DWORD, QWORD, MULTI_SZ,
    BINARY, and "delete value" entries); **Security** edits `GptTmpl.inf` (UTF-16LE) as a section/key/value table with
    suggestions for the common keys; **Files** browses, views, edits, uploads, downloads and deletes files and folders
    in the GPO's Machine/ and User/ folders (700 KiB limit, symlinks never followed); **Details** shows AD and SYSVOL
    versions (a mismatch is shown in red) and edits the client-side-extension lists.
  - Every settings change bumps the GPO's `versionNumber` (computer = low 16 bits, user = high 16 bits) and `GPT.INI`, and
    adds the matching client-side extension (Registry, Security) to `gPCMachineExtensionNames` / `gPCUserExtensionNames`
    so clients process it. Concurrent edits are refused by an etag (SHA-256 of the file).
  - Needs goaduc on the domain controller, as root: new `-sysvol` / `ADUC_SYSVOL` (default `/var/lib/samba/sysvol` when
    present). Without it the page still manages GPOs and links, and says SYSVOL is unavailable on the settings tabs.
  - Safety: a SYSVOL write is only attempted after the signed-in user's own LDAP modify of the GPO has succeeded (the
    version bump), so AD permissions still decide who may edit; all validation happens before that, so a refused request
    never changes a version number. Paths are validated (no `..`, no leaving the GPO folder, only Machine/ and User/).
- **Installer**: `--sysvol DIR` and `--run-as root|service|auto`. On a DC (SYSVOL found) the service runs as root (no
  `goaduc` user created, no `User=` in the unit, `ADUC_SYSVOL` in the config); elsewhere it runs as the `goaduc` user.
- Tests: Registry.pol byte vector and round trips (all types, malformed files), INI and encodings, extension-list merging,
  `gPLink` parsing, path safety and symlink escapes, and mock-DC integration tests for the whole lifecycle (create, link,
  order, options, inheritance, status, rename, extension lists, delete), registry/security/file edits with version bumps,
  stale etags, and the LDAP-permission gate.

### Changed
- The mock DC has a Policies container with a Default Domain Policy linked at the domain, and `mockSysvol` makes a scratch
  SYSVOL; `ADUC_MOCK_SERVE=1 go test -run TestMockServe` serves one.
- `CLAUDE.md` and README describe the Group Policy rules and the root-on-a-DC setup.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, also with `CGO_ENABLED=0`; cross-compiled for
  linux/amd64, arm64, arm, 386, riscv64; `node --check` on the scripts.
- Headless Chromium against the mock (dark): list, links tab, create a GPO, link it to an OU through the picker, add and
  save a Computer registry entry, add and save a security setting, create and edit a file inside Machine/ (the folder is
  kept after saving), change the status, delete (with its link), no script errors.
- Installer: `--run-as`/`--sysvol` in all combinations under a scratch root with a shim `systemctl` (root with SYSVOL, kept
  on upgrade, service user, none, bad values), plus uninstall `--purge`.

### Not verified
- Everything against a real Samba DC: the on-disk result being read by Windows/Linux clients, NT ACLs and ownership of
  files goaduc writes (they get 0644/0755 and no `security.NTACL`; `samba-tool ntacl sysvolreset` may be needed),
  `Registry.pol` and `GptTmpl.inf` as Windows tools parse them (written from [MS-GPREG] and the INI format only), the GPO
  object created over LDAP getting the right security descriptor, and link-order semantics (new link = lowest precedence,
  last `gPLink` entry = order 1, from the documentation, not observed).
- Preferences (Groups.xml etc.), ADMX/Administrative Templates UI, WMI filters, security filtering/delegation and Group
  Policy Results/Modeling are not implemented.
- `shellcheck` was not available.

## [v5] - 2026-11-10 — LDAP Browser tree shows containers only

### Fixed
- The LDAP Browser put every object in the left-hand tree (users, groups, computers and all). The tree now has only
  objects that can hold others (containers, OUs, domains, DNS zones, sites, servers and the like); everything else is
  in the list on the right. The server marks each item (`cont`) from its `objectClass` chain: `container` or any of a
  fixed set of container classes. Double-clicking a leaf in the browser list now opens its properties instead of
  trying to browse into it, and containers still sort first.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, also with `CGO_ENABLED=0`; cross-compiled for
  linux/amd64, arm64, arm, 386, riscv64; `node --check` on the scripts; a unit test for the class rules.
- Headless Chromium against the mock, LDAP Browser, all tree nodes expanded: only containers in the tree, `Infrastructure`
  (a leaf) in the list but not the tree, users only in the list, double-click on a user opens properties, no script errors.

### Not verified
- Against real Samba data. A container class that isn't `container`-derived and isn't in the fixed set would appear only in
  the list (browse into it from there with Open is not offered); say which class and it can be added to `containerClasses`.

## [v4] - 2026-11-10 — properties dialog wide enough for all its tabs

### Fixed
- The properties dialog had a fixed width (760 px), so the tab row (General … Member Of, Attributes) overflowed into a
  horizontal scrollbar and the last tabs were cut off, worse with a larger font. The dialog is now as wide as its tab row
  needs (at least 760 px, never more than 96% of the window) and the tab row wraps onto a second line on a narrow
  window instead of scrolling. The tab body does not influence the width, so the dialog no longer changes size when you
  switch tabs.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, also with `CGO_ENABLED=0`; cross-compiled for
  linux/amd64, arm64, arm, 386, riscv64; `node --check` on the scripts.
- Headless Chromium against the mock at 1280, 1000 and 640 px wide, user and group properties: no tab-row scrollbar and
  no page-level horizontal scroll; user tabs on one row at 1280 and 1000, two rows at 640.

### Not verified
- A computer object's properties dialog (the mock has no computer account to open), and the exact width with the system
  font and size on your machine; it sizes itself from the text, so a larger font gives a wider dialog.

## [v3] - 2026-11-10 — enable the AD Recycle Bin from the Recycle Bin page

Why the page said the Recycle Bin was not enabled: it is an optional AD feature that is off by default, and a Samba
domain does not switch it on when it is provisioned. Until it is on, deleting an object leaves a tombstone that has lost
most of its attributes and group memberships.

### Added
- **Enable Recycle Bin…** button on the Recycle Bin page, shown only when the feature is off, with a confirmation
  (forest-wide, cannot be undone). `POST /api/recyclebin/enable` does what `Enable-ADOptionalFeature` does: it adds
  `<CN=Partitions,CN=Configuration,…>:766ddcd8-acd0-445e-f3b9-a7f9b6744f2a` to the rootDSE attribute
  `enableOptionalFeature`, as the signed-in user, so AD's own permission check (Enterprise Admins) applies and a refusal
  is shown as is. Refused up front, with the `samba-tool` command to fix it, when the forest functional level is below
  2008 R2. Recorded in the audit log like any change.
- Tests: enable refused for a low forest level, refused for lack of rights (state unchanged), succeeds, second attempt
  reports "already enabled", and either record of the feature counts as enabled. The mock DC understands the rootDSE
  modify; `ADUC_MOCK_RB=off` starts the mock UI server with the feature off.

### Changed
- "Enabled" is now detected from `msDS-EnabledFeature` on the Partitions container as well as the feature object's
  `msDS-EnabledFeatureBL` back-link (either counts).
- The Recycle Bin page no longer has a message line: the "not enabled" warning is the button's state and tooltip, errors
  are red text in the toolbar, a truncated list is "(truncated)" on the count, and the "Restored…" text is gone.
- README explains the feature, its prerequisites and that it only protects objects deleted after it is on.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, also with `CGO_ENABLED=0`; cross-compiled for
  linux/amd64, arm64, arm, 386, riscv64; `node --check` on the scripts.
- Headless Chromium against the mock started with the feature off: button shown with tooltip, confirmation dialog, after
  enabling the button disappears, the Domain page reads "enabled", no message line, no script errors.

### Not verified
- Against a real Samba DC. The `enableOptionalFeature` value format is the documented Windows one and is what Samba's
  rootDSE module is understood to accept (forest level 2008 R2+), but it was only exercised against the mock. If your Samba
  refuses it, the error is shown on the page; the same change can be made with `ldbmodify` on the DC.
- Whether Samba maintains the `msDS-EnabledFeatureBL` back-link; detection therefore also accepts `msDS-EnabledFeature`.
- That restores then bring back group memberships (depends on the bin having been on at deletion time).

## [v2] - 2026-11-10 — remove the GUI banner and status message line

### Changed
- Removed the "Advanced: this is a raw view of the directory…" bar from the LDAP Browser page, and its styles.
- Removed the status-bar message line. The status bar now only carries the object count (with "(truncated)" and a tooltip
  when a list was cut off) and the realm. Progress and success text ("Loading…", "Searching…", "Query saved.", "Account
  unlocked.", "Password reset.", "Created …", and the like) is gone. A failure is plain red text at the end of the
  toolbar (no box, background or border) and clears on the next action.
- `CLAUDE.md`: updated the list of known leftovers.

### Verified
- `gofmt -l .`, `go build`, `go vet ./...`, `go test -race -count=1 ./...`, `node --check` on the three scripts.
- Headless Chromium against the mock, light and dark OS settings: no `.warnbar` or `#st-msg` on the Users, Sites and
  LDAP Browser pages, the count still updates, a bad search filter shows plain red text (no background) that clears after
  a good search, no JavaScript errors.

### Not verified
- Still present, and not touched: the `.pmsg` message lines on the DNS, Domain, Reports, Recycle Bin and Audit pages
  (`static/tools.js`), which still show progress and success text.

## [v1] - 2026-11-10 — first release: AD administration web UI for Samba 4, HTTPS by default, installer

goaduc is a browser-based set of Active Directory administration tools for a Samba 4 domain, written in Go with no
third-party dependencies. It talks to the directory over LDAPS (or LDAP with StartTLS) with a hand-written LDAPv3
client and runs every operation as the signed-in user, so AD's own permissions apply.

### Added
- **Users and Computers**: browse the OU/container tree; users (create, delete, reset password, enable/disable, unlock,
  move, rename), groups and membership, computers, OUs; search; attribute editor; logon hours, account expiry, log-on-to,
  profile, telephones, address, organization/manager, SPNs and delegation, managed-by; saved queries and a query builder.
- **Sites and Services**: sites, subnets, site links, servers, NTDS settings and connections; site creation with the
  Servers and NTDS Site Settings children and an optional site-link join.
- **DNS Manager**: zones and records (A, AAAA, CNAME, NS, PTR, MX, SRV, TXT, SOA) encoded to and decoded from the MS-DNSP
  `dnsRecord` format, with SOA serial bumping, CNAME exclusivity and a stale-record check on save. Zone create/delete is
  not supported.
- **Domain tools**: domain info and FSMO roles (read-only), default password policy and fine-grained password settings
  objects (PSOs), reports (stale users/computers, disabled, locked, never-expire, expiring, empty groups, no pre-auth,
  unconstrained delegation, privileged) and bulk user import from CSV, the AD Recycle Bin (list and restore), an
  LDAP/schema browser, and an audit log (in memory, optionally a JSON-lines file; passwords redacted).
- **HTTPS by default.** On first start a self-signed ECDSA P-256 certificate is generated in the data directory (key mode
  0600; SANs: host name, localhost, loopback and local interface addresses; regenerated within 30 days of expiry) and its
  SHA-256 fingerprint is logged. `-tls-cert/-tls-key` use your own; `-http` opts out; default listen is `:8443`.
  Flags and environment: `-listen`, `-server`, `-starttls`, `-insecure`, `-ca`, `-data-dir`, `-tls-cert`, `-tls-key`,
  `-http`, `-audit-log`, `-version` (`ADUC_*`).
- **Light and dark themes.** Follows the system setting; an Auto / Light / Dark button on the sign-in page and in the top
  bar overrides it and is remembered in the browser.
- **Installer** (`install.sh`, `uninstall.sh`, linked as `goaduc-uninstall`) for Ubuntu, Debian, Fedora, RHEL, Rocky,
  Alma, Arch, Manjaro and derivatives: builds from the tree with Go 1.24+ (found, installed from the distribution, or
  downloaded with a checksum check), creates an unprivileged `goaduc` user, installs `/usr/local/sbin/goaduc`, writes
  `/etc/goaduc/goaduc.conf` and a plain systemd unit, picks up the Samba CA automatically, upgrades in place keeping the
  config (including hand-added lines) and rolls back if the new version won't start. The systemd unit has no sandboxing
  or hardening directives, deliberately.
- `README.md`, this changelog, a GPLv3 `LICENSE`, and `CLAUDE.md` with the release process and project rules.

### Changed
- The web UI sends no HSTS header: it is per host, not per port, and the default certificate is self-signed.

### Verified
- `gofmt -l .` clean; `go build`, `go vet ./...`, `go test -race -count=1 ./...` pass; also with `CGO_ENABLED=0`.
- Cross-compiled for linux/amd64, arm64, arm, 386 and riscv64.
- Unit tests: BER and filter parsing, DNS record vectors and round-trips, policy conversions, audit redaction, certificate
  generation/renewal/serving (HTTPS client trusting the generated certificate, key mode 0600, no HSTS), version file.
- Integration tests through an in-memory mock domain controller and the real HTTP handlers (login, CSRF, every tool).
- UI driven in headless Chromium against the mock: login, the Users/Sites/DNS/Domain/Reports/Recycle/Browser/Audit pages,
  and the theme button in light and dark OS modes (cycle, persistence across reload, top bar).
- Binary run as the unprivileged service user: HTTPS answered, key 0600, certificate verified with `--cacert` for
  `localhost`.
- Installer: `bash -n`; `--dry-run` for ubuntu, debian, linuxmint, fedora, rocky, almalinux, centos, arch, manjaro and
  endeavouros (alpine refused), plus a run with tar/openssl/go assumed missing; real runs under a scratch root with a shim
  `systemctl`: fresh install, same-version no-op, upgrade keeping hand-edited config, forced-failure rollback, downgrade
  refusal, uninstall with and without `--purge`, uninstall → reinstall → purge removing the user the installer created,
  and a pre-existing user left alone. Go download tested against a local stub server, including a wrong-checksum refusal.
  Testing found and fixed: a failed unit-file write that was reported as "created", and a purge after uninstall →
  reinstall that forgot the installer had created the service user.

### Not verified
- Anything against a real Samba 4 DC: DNS record encoding (written from MS-DNSP, checked only against vectors and the
  mock), Recycle Bin restore, password-policy attribute conventions, in-chain group matching, `unicodePwd` resets, site
  and subnet creation. Field names and controls were seen only in the mock.
- The systemd unit under real systemd (the sandbox has none; a shim was used), and package installs through apt, dnf and
  pacman (dry run only).
- `shellcheck` was not available, so it was not run.
- Saved queries are kept in the browser's `localStorage`, and the FSMO page is read-only; both are limits, not bugs.
