# Start here

This source ZIP contains the Workglen Rust application, CLI installer, design and operation guides, configuration examples, tests, validation results and dependency notices. No repository access is required. [DOCUMENTATION.md](DOCUMENTATION.md) indexes the included documents and distinguishes implemented behavior from design/backlog material.

For the requested layout, run **Admin and Accounting on your Mac**, use your **existing local PostgreSQL** for Accounting, and run **Mail Security on Lightsail**. The gateway keeps its own encrypted redb store and continues working when the Mac is asleep or offline. PostgreSQL is not exposed to Lightsail.

Start with [MAC-ADMIN-LIGHTSAIL.md](MAC-ADMIN-LIGHTSAIL.md). On each machine, unpack this same ZIP and build the executable for that machine. The archive contains source, not a prebuilt macOS/Linux universal binary.

```sh
unzip workglen-0.8.0-source.zip
cd workglen
bash install.sh check
bash install.sh build
```

`check` is optional and read-only. `build` handles missing system prerequisites on Ubuntu/Debian, DNF-based Linux and macOS, installs missing Rust/Cargo from the official Rust distribution, downloads locked Cargo dependencies, then compiles. Run it as your normal login user without sudo; it requests sudo only for Linux system packages. On macOS, complete Apple's installation dialog if Command Line Tools are missing. No separate package-install commands are needed on the supported systems. See [INSTALL.md](INSTALL.md) for details and `--offline` builds.

The default release settings reduce compiler memory use and keep one build job. If a small Lightsail instance still kills the compiler, [INSTALL.md](INSTALL.md) explains how to confirm an out-of-memory kill and retry; the helper preserves the build cache.

On your Mac, prepare a private PostgreSQL connection file as explained in the Mac guide, then run the wizard:

```sh
bash install.sh admin --postgres-dsn-file "$HOME/workglen-postgres.dsn"
```

It asks for the gateway DNS name, mail domain, certificate settings, local Admin password and a separate gateway recovery password. It creates a local launch script and a private gateway pairing bundle. Follow the printed transfer/install instructions and the Mac guide.

For all switches:

```sh
bash install.sh --help
```

Existing configurations and data are never overwritten. This is a development release; read [VALIDATION.md](VALIDATION.md) for what was actually tested, including the macOS validation boundary. There are no deployed-version conversion/import steps. External accounting exchange remains a separate feature: see [ACCOUNTING.md](ACCOUNTING.md).
