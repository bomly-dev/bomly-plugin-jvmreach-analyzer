# bomly-plugin-jvmreach-analyzer

JVM reachability analyzer for [Bomly](https://github.com/bomly-dev/bomly-cli).

It discovers modules in Maven, Gradle, and sbt projects, scans Java, Kotlin,
and Scala sources for `import` statements, and annotates the vulnerabilities
Bomly already found with package-tier reachability: whether the vulnerable
artifact's packages are actually imported by your code. Results are cached on
disk under `~/.cache/bomly/analyze/jvmreach/` (24h TTL).

> **Safety note:** "unreachable" at any tier means the analysis found no path,
> not that the vulnerability is safe to ignore. Use reachability to prioritize,
> not to dismiss.

## Coverage

- **Ecosystems:** Maven, Scala (Maven, Gradle, sbt builds)
- **Languages:** Java, Kotlin, Scala
- **Tiers:** package
- **Requires:** nothing besides the sources — no JVM needed

## Embedded in the CLI

The Bomly CLI ships this same analyzer built in — `bomly scan --analyze` uses
it without installing anything. This repository packages the identical module
as a standalone managed plugin, for lite builds and for hosts that load
analyzers as external plugins.

## Install

Download the archive for your platform from the
[releases page](https://github.com/bomly-dev/bomly-plugin-jvmreach-analyzer/releases), then:

```sh
bomly plugin install ./bomly-plugin-jvmreach-analyzer_<version>_<os>_<arch>.tar.gz
bomly plugin enable jvmreach
bomly scan --enrich --analyze
```

## Configuration

The analyzer has no configuration keys. Reachability is switched on with the
host's `--analyze` flag (or the matching config key); caching is on by default
and lives under `~/.cache/bomly/analyze/jvmreach/` with a 24-hour TTL.

## Local development

```sh
go build -o bin/bomly-plugin-jvmreach-analyzer ./cmd/bomly-plugin-jvmreach-analyzer

# Install the dev build into Bomly and scan
bomly plugin install ./bin/bomly-plugin-jvmreach-analyzer --dev
bomly plugin enable jvmreach
bomly scan --enrich --analyze
```

Run the tests (unit + SDK conformance + a real gRPC handshake probe):

```sh
go test ./...
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
