# AWS ALB Access Log Detections Mod

[Tailpipe](https://tailpipe.io) is an open-source CLI tool that allows you to collect logs and query them with SQL.

The [AWS ALB Access Log Detections Mod](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-alb-access-log) contains pre-built dashboards and detections, which can be used to monitor and analyze activity across your AWS Application Load Balancers.

## Documentation

- **[Dashboards →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-alb-access-log/dashboards)**
- **[Benchmarks and detections →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-aws-alb-access-log/benchmarks)**

## Getting Started

Install Powerpipe from the [downloads](https://powerpipe.io/downloads) page:

```sh
# MacOS
brew install turbot/tap/powerpipe
```

```sh
# Linux or Windows (WSL)
sudo /bin/sh -c "$(curl -fsSL https://powerpipe.io/install/powerpipe.sh)"
```

This mod also requires AWS ALB access logs to be collected using [Tailpipe](https://tailpipe.io) with the [AWS plugin](https://hub.tailpipe.io/plugins/turbot/aws):
- [Get started with the AWS plugin for Tailpipe →](https://hub.tailpipe.io/plugins/turbot/aws#getting-started)

Install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod install github.com/turbot/tailpipe-mod-aws-alb-access-log
```

### Browsing Dashboards

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Benchmarks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run aws_alb_access_log.benchmark.security
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).