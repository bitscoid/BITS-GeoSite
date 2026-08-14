# BITS-GeoSite

Automated **GeoSite database and sing-box rule-set builder** for global domain
data. Source data comes from the latest
[`v2fly/domain-list-community`](https://github.com/v2fly/domain-list-community)
release, enriched with community ad-block and Indonesia-focused lists.

Generated data targets [sing-box](https://github.com/SagerNet/sing-box) and is
published by [bitscoid/BITS-GeoSite](https://github.com/bitscoid/BITS-GeoSite)
through GitHub Releases plus the `release`, `rule-set`, and `rule-set-unstable`
branches.

<p>
  <img src="https://img.shields.io/badge/Platform-Cross--platform-00ADD8?logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Generated%20for-sing--box-7C3AED?logo=go&logoColor=white" alt="sing-box" />
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License" />
</p>

---

## Table of Contents

- [What is generated](#what-is-generated)
- [Variants](#variants)
- [Rule categories](#rule-categories)
- [Usage in sing-box](#usage-in-sing-box)
- [Requirements](#requirements)
- [Local usage](#local-usage)
- [Environment variables](#environment-variables)
- [Development](#development)
- [Processing flow](#processing-flow)
- [GitHub Actions](#github-actions)
- [Versioning](#versioning)
- [Related projects](#related-projects)
- [License](#license)

---

## What is generated

| File | Description |
| --- | --- |
| `geosite.db` | **Full** GeoSite database (all v2fly categories + extra lists). |
| `geosite-min.db` | **Minimal** GeoSite database: `id`, `rule-ads`, `rule-indo`. |
| `geosite.db.sha256sum` | SHA-256 checksum of the full database. |
| `geosite-min.db.sha256sum` | SHA-256 checksum of the minimal database. |
| `rule-set/geosite-<tag>.srs` | Stable sing-box binary rule set (one per category). |
| `rule-set-unstable/geosite-<tag>.srs` | Unstable (category-custom) rule sets. |
| `rule-set.tar.gz` | Archive of all generated rule sets. |

## Variants

| Variant | Contents | Size (approx.) | Typical use |
| --- | --- | --- | --- |
| **Minimal** (`geosite-min.db`) | `id`, `rule-ads`, `rule-indo` | ~5 KB | Bundled in the [BITS Box](https://github.com/Banten-IT-Solutions/BITS-Box) APK; covers default route rules. |
| **Full** (`geosite.db`) | Every v2fly category + extra lists | ~32 MB | When rules reference categories beyond the minimal set. |

## Rule categories

### From `v2fly/domain-list-community`

Hundreds of categories split into two groups:

- **Per-platform / brand:** `apple`, `google`, `google-play`, `facebook`,
  `instagram`, `twitter`, `telegram`, `netflix`, `youtube`, `spotify`,
  `discord`, `steam`, `epicgames`, `microsoft`, `amazon`, `cloudflare`,
  `github`, `openai`, ...
- **Grouped `category-*`:** `category-ads-all`, `category-ai-!cn`,
  `category-games-!cn`, `category-media-!cn`, `category-social-media-!cn`,
  `category-cryptocurrency`, `category-communication`, `category-porn`,
  `category-ip-geo-detect`, `geolocation-!cn`, `geolocation-cn`, ...

### Extra lists added by this generator

Downloaded live from their upstream sources during generation:

| Category | Source | Purpose |
| --- | --- | --- |
| `oisd-full`, `oisd-small`, `oisd-nsfw` | big.oisd.nl | Ad / tracker blocklists |
| `d3ward`, `rule-ads` | Turtlecute33/adblocktest, malikshi/v2ray-rules-dat | Ad blocking |
| `antiscam`, `rule-malicious` | malikshi/antiscam, Inversion-DNSBL | Security / scam |
| `rule-doh`, `rule-gaming`, `rule-playstore` | malikshi/v2ray-rules-dat | DoH, gaming, Play Store |
| `rule-indo`, `rule-sosmed`, `rule-streaming` | malikshi/v2ray-rules-dat | Indonesia, social, streaming |
| `rule-umum`, `rule-ipcheck`, `rule-speedtest` | malikshi/v2ray-rules-dat | General, IP check, speedtest |
| `videoconference`, `urltest` | malikshi/v2ray-rules-dat | Video calls, URL testing |

## Usage in sing-box

Reference categories in rules with the `geosite:` prefix:

```json
{
  "rules": [
    { "domain": ["geosite:rule-ads"], "outbound": "block" },
    { "domain": ["geosite:rule-indo"], "outbound": "direct" },
    { "domain": ["geosite:netflix"], "outbound": "proxy" },
    { "domain": ["geosite:category-porn"], "outbound": "block" }
  ]
}
```

Or use the binary rule sets:

```json
{ "rule_set": ["geosite-netflix"], "outbound": "proxy" }
```

with `rule_set` defined pointing to a local `.srs` file from the `rule-set/`
directory or to a remote `https://raw.githubusercontent.com/.../geosite-netflix.srs`.

> **Note:** rules referencing a category that is missing from the loaded
> database are skipped silently. With the minimal database only `id`,
> `rule-ads`, and `rule-indo` are available.

## Requirements

- Go version declared in [`go.mod`](go.mod).
- Network access to GitHub Releases.
- GitHub token only when higher API rate limits are needed.

## Local usage

```sh
go run .                        # build latest upstream data
NO_SKIP=true go run .           # force regeneration (skip already-latest check)
FIXED_RELEASE=<release-tag> go run .   # pin a specific upstream release
make build                      # compile to ./bits-geosite
```

The generator queries the upstream repo, downloads data, generates the
databases and rule sets, then **publishes** them to the destination repo
(GitHub Releases + branches).

## Environment variables

| Variable | Description |
| --- | --- |
| `ACCESS_TOKEN` | GitHub token for authenticated API requests. |
| `FIXED_RELEASE` | Upstream release tag to build instead of latest. |
| `NO_SKIP` | Set to `true` to force regeneration (bypasses the already-latest skip). |

## Development

```sh
make fmt           # Format Go source (gofumpt + gofmt + gci)
make fmt_install   # Install formatting tools
make lint          # Run golangci-lint
make test          # Run Go package tests
make build         # Build ./bits-geosite
make clean         # Remove generated artifacts
```

Generated artifacts are ignored by Git through [`.gitignore`](.gitignore).

## Processing flow

1. Query the latest or pinned upstream GitHub release.
2. Download and verify `dlc.dat` using its SHA-256 checksum.
3. Parse domain entries and attributes.
4. Fetch extra lists (`oisd`, `rule-*`, `d3ward`, ...) and merge them.
5. Generate the complete database (`geosite.db`).
6. Generate the minimal database (`geosite-min.db`) from `id`, `rule-ads`, `rule-indo`.
7. Generate stable and unstable sing-box rule sets.
8. Publish databases, checksums, rule sets, and `rule-set.tar.gz`.

## GitHub Actions

### `build.yaml`

Runs on pushes to `main`. Checks out, installs Go, lints, builds the data with
`NO_SKIP=true`, and uploads generated artifacts.

### `release.yaml`

Runs **daily** (cron `0 0 * * *`) or manually. Supports two inputs:

| Input | Description |
| --- | --- |
| `tag` | Optional upstream release tag to build instead of latest. |
| `force` | Set `true` to force regeneration (passes `NO_SKIP=true`). |

It publishes checksums and `rule-set.tar.gz`, keeps the **three latest**
releases, and pushes generated files to the `release`, `rule-set`, and
`rule-set-unstable` branches.

Published branches:

- [`release`](https://github.com/bitscoid/BITS-GeoSite/tree/release) — databases + checksums.
- [`rule-set`](https://github.com/bitscoid/BITS-GeoSite/tree/rule-set) — stable rule sets.
- [`rule-set-unstable`](https://github.com/bitscoid/BITS-GeoSite/tree/rule-set-unstable) — unstable rule sets.

## Versioning

Release tags mirror the upstream `v2fly/domain-list-community` release tag
(e.g. `20260814022505`), so a fresh release is only created when upstream
publishes new data. Old releases are pruned to the three most recent.

## Related projects

- [BITS-GeoIP](https://github.com/bitscoid/BITS-GeoIP) — GeoIP database builder.
- [BITS-Box](https://github.com/Banten-IT-Solutions/BITS-Box) — Android client that consumes these assets.
- [sing-box](https://github.com/SagerNet/sing-box) — the target kernel.
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) — upstream domain data.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
