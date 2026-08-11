# BITS-GeoSite

Automated GeoSite database and sing-box rule-set builder for global domain
data. Source data comes from the latest `v2fly/domain-list-community` release.

Generated data targets [sing-box](https://github.com/SagerNet/sing-box) and is
published by [bitscoid/BITS-GeoSite](https://github.com/bitscoid/BITS-GeoSite)
through `release`, `rule-set`, and `rule-set-unstable` branches, plus GitHub
Releases.

## Generated files

| File | Description |
| --- | --- |
| `geosite.db` | Complete GeoSite database. |
| `geosite-id.db` | Indonesia-focused GeoSite database. |
| `rule-set/geosite-<tag>.srs` | Stable sing-box rule set. |
| `rule-set-unstable/geosite-<tag>.srs` | Unstable sing-box rule set. |

## Requirements

- Go version declared in [`go.mod`](go.mod).
- Network access to GitHub Releases.
- GitHub token only when higher API rate limits are needed.

## Local usage

```sh
go run .
NO_SKIP=true go run .
FIXED_RELEASE=<release-tag> go run .
make build
```

## Environment variables

| Variable | Description |
| --- | --- |
| `ACCESS_TOKEN` | GitHub token for authenticated API requests. |
| `FIXED_RELEASE` | Upstream release tag to build instead of latest. |
| `NO_SKIP` | Set to `true` to force regeneration. |

## Development

```sh
make fmt
make lint
make test
make build
make clean
```

Generated artifacts are ignored by Git through [`.gitignore`](.gitignore).

## Processing flow

1. Query the latest or pinned upstream GitHub release.
2. Download and verify `dlc.dat` using its SHA-256 checksum.
3. Parse domain entries and attributes.
4. Generate complete and Indonesia-focused databases.
5. Generate stable and unstable sing-box rule sets.
6. Publish release artifacts and generated branches through GitHub Actions.

## GitHub Actions

`build.yaml` runs checks and uploads generated artifacts on pushes to `main`.
`release.yaml` runs daily or manually, supports an optional upstream tag,
publishes checksums and `rule-set.tar.gz`, and keeps three latest releases.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
