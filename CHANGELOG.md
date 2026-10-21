# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-21

### Added

- Authum client module (ABI 0.3) for classic HLDS — geo / proxy filter + Steam session guard
- IPHub lookup with SQL cache (SQLite default or MySQL/MariaDB via Authum SQL brick)
- Country allow/deny list, block-score kicks, whitelist (ASN / IP / SteamID / flags)
- `steam_guard` — ASN (+ optional country) history per SteamID; learn mode by default (`enforce=0`)
- SQL connect delay/retry for MariaDB that starts with HLDS
- Clear player-facing reject reasons (country / proxy) instead of a generic kick string
- Event `gatekeeper.client.resolved` for other modules
- Docs: install, SQL schema, `docs/sql-setup.md`
- Linux i386 CI + Release: Authum module zip (`addons/authum/modules/gatekeeper/`)

[Unreleased]: https://github.com/darwin128k/raspad-gatekeeper/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/darwin128k/raspad-gatekeeper/releases/tag/v0.1.0
