# PocketBase-compatible server in Rust

> This PocketBase (Rust) I used for my personal-side project. I really love PocketBase because simple, lightweight and fast.
And I really appreciate, thanks to Gani Georgiev for creating this cool project.

[![CI](https://github.com/HilmiZul/pb-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/HilmiZul/pb-rs/actions/workflows/ci.yml)
[![Release](https://github.com/HilmiZul/pb-rs/actions/workflows/release.yml/badge.svg)](https://github.com/HilmiZul/pb-rs/actions/workflows/release.yml)

## Build

```sh
cargo build --release -p pb-cli
# binary: target/release/pocketbase
```

## Prebuilt binaries

Every push to `main` runs the [Release](.github/workflows/release.yml) workflow.
It computes the next version, builds all supported targets on GitHub-hosted
runners, generates the release notes from the commit history, creates the
matching `vX.Y.Z` tag and publishes a GitHub release.

| OS      | Architecture | Archive name                                    |
| ------- | ------------ | ----------------------------------------------- |
| macOS   | arm64        | `pocketbase-rs_<version>_darwin_arm64.zip`      |
| macOS   | amd64        | `pocketbase-rs_<version>_darwin_amd64.zip`      |
| Linux   | amd64        | `pocketbase-rs_<version>_linux_amd64.zip`       |
| Linux   | arm64        | `pocketbase-rs_<version>_linux_arm64.zip`       |
| Windows | amd64        | `pocketbase-rs_<version>_windows_amd64.zip`     |
| Windows | arm64        | `pocketbase-rs_<version>_windows_arm64.zip`     |

Each archive contains the `pocketbase` binary (`pocketbase.exe` on Windows),
`CHANGELOG.md`, `LICENSE.md`, `README.md` and the admin UI under `ui/_/`.
Extract the **whole** archive and run the binary from that folder — the UI is
loaded from `ui/_` next to the executable.

On the first run with an empty data directory the server creates an installer
superuser and prints a `/_/#/pbinstall/<token>` URL. Open it (or follow the
printed link) to register your first real superuser. You can also create one
from the CLI: `pocketbase superuser upsert EMAIL PASS`.

The version is bumped automatically (patch level) from the latest tag. To cut a
specific version, either run the Release workflow manually with a `version`
input or push a tag yourself:

```sh
git tag v0.2.0
git push origin v0.2.0
```

Release notes and `CHANGELOG.md` are generated from the commit history with
[git-cliff](https://git-cliff.org), grouping conventional commit types into
sections. Linux builds are produced on Ubuntu 22.04 and require glibc 2.35 or
newer.

The macOS binaries are not code-signed or notarized. If Gatekeeper blocks a
downloaded build, remove the quarantine attribute:

```sh
xattr -d com.apple.quarantine ./pocketbase
```

## License

PocketBase (c) Gani Georgiev; see `LICENSE.md`.
