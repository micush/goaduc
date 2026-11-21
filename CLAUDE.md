# Instructions for Claude working on this project

goaduc is a Go web application that administers a Samba 4 Active Directory domain over LDAP/LDAPS: a browser
clone of Users and Computers (ADUC), Sites and Services, DNS Manager, password policy and fine-grained PSOs, reports and
CSV import, the AD Recycle Bin, domain/FSMO information, an LDAP/schema browser and an audit log. It is stdlib-only
Go with a hand-written LDAPv3 client (`ldapc.go`), a vanilla-JS front end embedded with `go:embed` (`static/`), and a
systemd installer (`install.sh`, `uninstall.sh`). This file is a standing instruction from the project owner so it
doesn't need repeating each conversation. If you (Claude) are asked to change this project, follow the process below
without being told to.

## Release process — do this for every request that changes the project

1. **Do the requested work** (code, docs, config, whatever was asked).

**Layout.** The tarball has one top-level directory, `goaduc/`, and the Go module is flat inside it: `go.mod`, every
`*.go`, `static/` (the web UI: `app.js`, `tools.js`, `gpo.js`, `theme.js`, `style.css`), `VERSION` (must sit next to the Go files because `main.go` embeds it), `README.md`, `snaps/` (PNG screenshots the README embeds; retake them from the mock UI when a page's look changes),
`CHANGELOG.md`, `LICENSE` (GPLv3), `install.sh`, `uninstall.sh`, `get.sh` (the `curl | bash` web installer: fetches the newest tag from GitHub and runs its `install.sh`; keep it working with the layout and `VERSION` rules here) and this file. All Go commands below run in the
top of the tree. The installer expects `go.mod`, `main.go` and `VERSION` next to `install.sh`.
Files: `ldapc.go` (BER, filters, LDAP client), `main.go` (sessions, auth middleware, ADUC handlers, routes, `main()`),
`sites.go` (Sites and Services create), `dns.go` (MS-DNSP record encode/decode, zone/record API), `tools.go` (domain
info, policy/PSO, reports, recycle bin, audit), `gpo.go` (Group Policy objects, links, version/extension bookkeeping, `gpoCommit`), `gpofiles.go` (SYSVOL: GPT.INI,
Registry.pol, GptTmpl.inf, plain files), `update.go` (the Update page: archive unpack, build, swap, boot guard), `tlscert.go` (self-signed web certificate), `webcert.go` (Settings → Certificate: upload, live swap, reset), `webcert_test.go`, `gpo_test.go`, `update_test.go`, `mock_test.go` (in-memory
mock domain controller + integration tests), `ldapc_test.go`, `tools_test.go`.

2. **Build and test before packaging, not after.** From the top of the tree run `gofmt -l .` (must print nothing),
   `go build -o /dev/null .` (a bare `go build` drops a `goaduc` binary in the tree — delete it if it appears),
   `go vet ./...` and `go test -race -count=1 ./...`; also `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`
   (the shipped binary is static, so that is the configuration that matters). Don't skip straight to packaging on a
   change that could plausibly have broken something. Beyond the unit tests:
   - **Touched the LDAP client (`ldapc.go`) or the filter parser?** `ldapc_test.go` covers BER and filters; add a case
     for what you changed. The mock server in `mock_test.go` evaluates filters with its own BER evaluator, so a filter
     test passes against the mock only if both sides agree — check the RFC 4515 / MS extensible-match semantics, not
     just that it compiles.
   - **Touched DNS (`dns.go`)?** The record encoding follows MS-DNSP (24-byte header, `DNS_COUNT_NAME`, big-endian
     TTL/SRV/MX/SOA fields). `TestDNSRecordVectors` holds byte-for-byte vectors; a deliberate encoding change means new
     vectors with a stated source — never quietly edit the vectors to make the test pass.
   - **Touched Group Policy (`gpo.go`, `gpofiles.go`, `static/gpo.js`)?** Settings are files in SYSVOL written by this
     process (as root), not by the signed-in user, so the rules are strict and each has a test in `gpo_test.go`: every
     write goes through `gpoCommit`, which runs `prepare` (all validation: path, etag, content) first, then an LDAP
     modify of `versionNumber` as the signed-in user (the permission gate: a user who may not edit the GPO in AD never
     causes a file write; `TestGPOWriteNeedsLDAPRight`), then the write, then `GPT.INI`; a refused request must not bump
     the version. Paths go through `safeRel`/`gpoPath` (no `..`, no symlinks out of the GPO folder, case-insensitive
     match of existing parts) and only `Machine/` and `User/` can be changed. `Registry.pol` is `[MS-GPREG]`: keep the
     byte-exact vector in `TestPolVectorAndRoundTrip`; `GptTmpl.inf` is written UTF-16LE with a BOM and CRLF. Writes
     carry an etag so a concurrent edit is refused. The mock has no SMB and no NT ACLs: say so in the changelog, and say
     what was not seen on a real Samba DC (permissions/ownership of written files, client processing).
   - **Touched the updater (`update.go`, `static/tools.js` Update page, `get.sh`)?** It runs uploaded or downloaded source
     through `go build` as the service user (usually root) and replaces the running binary, so the rules are strict and
     each has a test in `update_test.go`: only a Domain/Enterprise Admin verified over the user's own LDAP connection
     (`isDomainAdmin`) may start one, and `-no-update` refuses everyone; the archive is unpacked by `extractUpdate`
     (no `..`, absolute, link or special entries, size and count limits); only a strictly newer integer `VERSION` is
     accepted; the build is `CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off` (never a network fetch); the built binary must
     answer `--version` with the new version before anything is replaced; the old binary is saved first (the installer's
     `goaduc.prev`) and the boot guard restores it after `maxBootAttempts` failed starts. A refused update must leave the
     binary and state untouched (`TestUpdateRefusalsChangeNothing`). Never skip TLS verification for the GitHub fetch.
     `get.sh`: `bash -n`, `shellcheck -x -S warning` if installed, and run it against a local fake GitHub
     (`python3 -m http.server` with `GOADUC_GET_REPO/API/HOST`): latest release, tags fallback, `--version`, a bad tag, a
     bad or missing `VERSION`, a project in a `goaduc/` folder, piped from stdin. A real apply (re-exec of the real binary
     under systemd) cannot be seen in the sandbox: say so.
   - **Touched the Recycle Bin enable fallback (`apiRecycleEnable`, `ldbModifyLocal`, and the purge fallback `apiPurge` with `sambaToolRun` / `ldbDelLocal`)?** It is the second exception to
     "everything runs as the signed-in user": only after the user's own LDAP request was refused (code 50/53), only as
     root with `sam.ldb` present, only after `isEnterpriseAdmin` (for the purge fallback: `isDomainAdmin`, Domain or Enterprise
     Admin) is confirmed over the user's own connection, and it is logged. Keep the refusal cases covered in
     `TestRecycleBinEnable` and `TestPurgeLocalFallback`.
   - **Touched anything that writes to the directory?** Every write runs as the signed-in user over their own LDAP
     connection (AD's ACLs decide), is recorded by `audit()` with passwords redacted, and goes through the validators
     (DN escaping, CIDR, sitelink cost, policy ranges). Add a test through the mock for the new path, including the
     refusal case (protected objects: `isProtectedDN`).
   - **Touched the web server, sessions or TLS (`main.go`, `tlscert.go`)?** The tests must cover what you changed
     (CSRF header, cookie flags, empty-password refusal, idle expiry, certificate generation/renewal). Never weaken an
     auth/CSRF test to make it pass. Run the real binary once: start it as an unprivileged user with a scratch
     `-data-dir`, `curl -sk https://127.0.0.1:<port>/`, check the key is mode 0600 and the certificate verifies with
     `--cacert` against `localhost`.
   - **Touched the UI (`static/`)?** `node --check static/app.js static/tools.js static/theme.js` at minimum. For real
     behaviour serve the mock (`ADUC_MOCK_SERVE=1 go test -run TestMockServe -timeout 0` serves a mock LDAP on
     127.0.0.1:3389 and the UI on 127.0.0.1:8099, any user/password) and drive it with headless Chromium (Playwright is
     installed in the sandbox; use `colorScheme: "light"` and `"dark"`): log in, click through the pages you touched,
     look at a screenshot. Hard rules for the front end: no inline `<script>` / `style=` attributes that carry script,
     and no `innerHTML` on data (the CSP forbids the first and the second is an XSS hole — build DOM with the `h()`
     helper, which uses `textContent`); every JSON list the UI maps over must serialise as `[]`, never `null` (initialise
     Go slices non-nil); never pass `null` children to `h()`/`append`.
   - **Touched `install.sh` / `uninstall.sh`?** They run as root on other people's machines, so: `bash -n` +
     `shellcheck -x -S warning` clean (say so in the changelog if shellcheck isn't installed); a `--dry-run` per family
     using `GOADUC_OS_RELEASE` with fake os-release files (ubuntu, debian, linuxmint, fedora, rocky, almalinux, centos,
     arch, manjaro, endeavouros; alpine must be refused) plus `GOADUC_ASSUME_MISSING=tar,openssl,go
     GOADUC_FORCE_GO_DOWNLOAD=1` (dnf needs a stub `dnf` in `PATH` on Debian-family sandboxes); then a real run in the
     sandbox under a scratch root (`GOADUC_PREFIX=...`) with a shim `systemctl` (`GOADUC_SYSTEMCTL`,
     `GOADUC_FORCE_SYSTEMD=1`, `GOADUC_SETTLE=0`; the shim must not let the installer's own "was it running" pre-check
     consume a forced failure): fresh install, same-version no-op, upgrade (copy the tree, bump its VERSION) keeping
     the config including hand-added lines, forced-failure rollback, downgrade refusal, uninstall with and without
     `--purge`, uninstall → reinstall → `--purge` still removing a user the installer created, and a pre-existing
     `goaduc` user surviving `--purge`; `--run-as` / `--sysvol`: root with SYSVOL (no user created, no `User=` in the unit,
     `ADUC_SYSVOL` in the config, kept on upgrade), `--run-as service` (user and `User=`/`Group=` present), no SYSVOL (service
     user), and bad values refused. Test the Go download against a local `python3 -m http.server` via
     `GOADUC_GO_BASE_URL` (go.dev may be unreachable from the sandbox), including a wrong-checksum refusal. Undo every
     sandbox change afterwards (user/group `goaduc`, scratch roots). The uninstaller never deletes config or state
     without `--purge`, and never removes a user/group it didn't create. A failed write must abort the installer, never
     print "created".
   - **Added/changed a page, a flag or a setting?** Update `README.md` (flags and env vars are listed there and in
     `install.sh --help`, `goaduc -h`, and the installer-written `goaduc.conf`; keep them in step).
3. **Cross-compile every release**, not just once — a later change can silently break a platform nothing here runs.
   For each of `linux/amd64`, `linux/arm64`, `linux/arm`, `linux/386`, `linux/riscv64` run
   `GOOS=<os> GOARCH=<arch> go build -o /dev/null .`. The installer is Linux-only; don't promise other OSes. If a new
   target is added, add it to this list in the same change.
4. **Bump `VERSION`.** It's a single plain integer (no `v` prefix, no semver) at `VERSION`, embedded into the binary
   (`goaduc --version` prints `goaduc vN`, which the installer parses). Increment it by exactly 1. `TestVersionIsPlainInteger`
   fails if the file is malformed — fix the file, don't weaken the test.
5. **Append a new entry to the top of `CHANGELOG.md`**, immediately below the `# Changelog` header (and any
   `## [Unreleased]` line), in the style of the existing entries: `## [vN] - YYYY-MM-DD — <short summary>` where `N` is
   the new VERSION and the date is the date of the change, then `### Added` / `### Fixed` / `### Changed` sections as
   appropriate, plus `### Verified` and `### Not verified`. Say what changed, why, and exactly what was run. Do not
   rewrite or renumber older entries.
6. **Repackage the whole project into a `.tgz`** named `goaduc_v<VERSION>.tgz` with the project directory itself
   (`goaduc/`) at the top of the archive, so it re-extracts to `goaduc/`. Source only: no built binaries, no scratch
   files, no `.tmp` leftovers (check `tar tzf` before handing it back).
7. **Hand the `.tgz` back** as the deliverable. Don't just describe the changes — the person expects a fresh archive
   every time, without having to ask.

Do steps 4–5 after every other file change (including this file and the README), so the version and changelog describe
the final tree.

## Notes

- **NO BANNERS. Ever.** Never add a banner, notice bar or status message line to the GUI: not for progress
  ("Loading…"), not for success ("Saved"), not for info or warnings. State goes in the control itself (tooltip, button
  label, a few words of small text beside it, a row's colour). Not even a red one: no box, no bar, no background, no
  border. A failure the person must act on is plain red text (no box) beside the control that failed, and nothing else.
  When touching a page, remove any banner you find in the code you are changing. Failures in the Users and Computers /
  Sites / LDAP Browser views are plain red text at the end of the toolbar (`status(msg, true)` → `#st-err`); there is no
  progress or success text. *Known leftovers, remove when touching them:* the `.pmsg` message lines on the pages in
  `static/tools.js` (`pageStatus`, DNS, Domain, Reports, Audit), which still show progress and success text. The Recycle
  Bin page is already clean: errors are red text in its toolbar and the "not enabled" state is the *Enable Recycle Bin…*
  button.
- **GUI text: keep it short.** Don't add explanatory paragraphs, hints or notes to pages, forms or tables. A label, a
  placeholder and at most a few words of hint are the limit. Explanations belong in `README.md`. Don't add any text the
  owner didn't ask for.
- The process applies to substantive changes (features, fixes, docs, refactors). Pure Q&A that changes nothing on disk
  needs no version bump. A pure packaging fix (archive name, permissions, layout) that changes nothing in the code,
  tests or behaviour doesn't need a bump: note it under the current version's changelog entry in a short
  `### Packaging fix` subsection and keep the archive name matching. If a request is big enough to split into several
  changelog-worthy pieces in one sitting, one bump and one entry covering all of it is fine, and one `.tgz`.
- Keep changelog entries specific about what was built or fixed and why, and honest about what wasn't verified. The
  hardest parts of this project to verify — behaviour against a real Samba DC (DNS record encoding, the Recycle Bin
  restore control, policy attribute conventions, in-chain matching, unicodePwd) and the systemd unit under real
  systemd — can't be exercised in the sandbox; say "not verified" rather than implying they were.
- **Dependencies: none, on purpose.** The module has no third-party requirements (the Go module proxy is not reachable
  from the sandbox anyway). Never disable checksum or TLS verification to get a module. Don't add a module for something
  small; if one is truly warranted, say so in the changelog.
- **systemd unit: no hardening directives.** The unit is deliberately plain (`User=`/`Group=` only with `--run-as service`; on a
  DC it runs as root so it can write SYSVOL; `EnvironmentFile=`,
  `Restart=`, `LimitNOFILE=`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` so a low port works). The owner has had
  repeated problems with sandboxing options (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`, `MemoryDenyWriteExecute`,
  `ReadWritePaths`, and the like). Do not add any of them back.
- **Theme.** The UI follows `prefers-color-scheme` automatically, and an Auto / Light / Dark button (top bar and sign-in
  page, remembered in `localStorage`, applied by `static/theme.js` loaded in `<head>` before first paint) lets the person
  override it. Colours are CSS variables on `:root`; a dark override exists both under the media query
  (`:root:not([data-theme=light])`) and under `:root[data-theme=dark]`. Anything with its own colours needs both. Check
  new UI in light and dark.
- Name: the project is goaduc. "ADUC" stays in cookie, header and environment-variable names (`aduc` cookie,
  `X-Requested-With: aduc`, `ADUC_*`) — that is identity for existing installs; don't rename it in a branding cleanup.
- Web GUI invariants (don't regress without saying so in the changelog):
  - Every LDAP operation runs as the signed-in user (exceptions: SYSVOL file writes, the Recycle Bin local fallbacks and the Update page's build and binary swap are done by the
    service process, gated as described in the release notes above): the server keeps that user's credentials and one LDAP connection per
    session, so AD's own ACLs apply. There is no service account with extra rights. An empty password is never sent as a
    bind.
  - Sessions are random tokens in HttpOnly, SameSite=Strict cookies, `Secure` when served over TLS; idle sessions expire
    (30 min janitor); every non-GET request needs the `X-Requested-With: aduc` header.
  - HTTPS is the default: a self-signed ECDSA certificate is generated on first start in the data directory (key 0600,
    directory 0700, regenerated within 30 days of expiry); explicit `-tls-cert/-tls-key` must exist and are never
    regenerated; plain HTTP only with `-http`, with a warning on non-loopback addresses. **No HSTS header** (it is per
    host, not per port, and the certificate is self-signed by default).
  - The audit log records who did what and never a password (any field whose name contains `pass` or `pwd`, other than
    `pwdLastSet`, plus `pw`/`pw2`, is redacted before it reaches the ring buffer or the file).
  - Password set/reset needs an encrypted LDAP connection (ldaps:// or StartTLS); never send `unicodePwd` in the clear.
  - Content-Security-Policy stays `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'`; the
    front end is external files only.
  - Protected objects (the domain root and the built-in configuration containers, `isProtectedDN`) can't be deleted,
    moved or renamed through the UI.
- Never let the LDAP code verify less than it was told to: `-insecure` is the only way to skip certificate
  verification of the directory, and it is an explicit, warned-about opt-in.
- If you are a future Claude, in any session type, asked to work on this project and this file's process hasn't been
  mentioned, read this file before starting anyway.
