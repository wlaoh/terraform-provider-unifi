# Unifi Terraform Provider (terraform-provider-unifi)

[![Fork acceptance tests](https://github.com/wlaoh/terraform-provider-unifi/actions/workflows/acctest.yaml/badge.svg)](https://github.com/wlaoh/terraform-provider-unifi/actions/workflows/acctest.yaml)

> **Note**: You can't (for obvious reasons) configure your network while connected to something that may disconnect (like the WiFi). Use a hard-wired connection to your controller to use this provider.

This fork builds with a local copy of the `go-unifi` SDK. Its [provenance and update instructions](third_party/go-unifi/README.md) describe how to keep the provider's controller changes when updating the SDK.

## Documentation

Use the [documentation in this checkout](docs/index.md) for the fork's [resources](docs/resources) and [data sources](docs/data-sources). The Terraform Registry documents the [published upstream provider](https://registry.terraform.io/providers/ubiquiti-community/unifi/latest/docs).

## Supported Unifi Controller Versions

Controller compatibility varies by feature and firmware. The acceptance workflow exercises the current controller container. Hardware-specific settings and Integration API resources also depend on the console model, firmware and authentication method. Use the resource documentation for prerequisites.

For an existing site, import one object first and run a normal plan to verify it has no pending changes. Terraform 1.14 or later also supports discovery with the provider's list resources.

## Using this fork locally

Build this checkout with the Go version in `go.mod`:

```shell
mkdir -p "$PWD/.local-bin"
go build -o "$PWD/.local-bin/terraform-provider-unifi" .
```

Add the following entry to a development Terraform CLI configuration, replacing the path with the absolute path printed by `pwd` plus `/.local-bin`. Select that CLI configuration with `TF_CLI_CONFIG_FILE` only in workspaces intended to run this fork. It keeps the existing provider address in configuration and state.

```hcl
provider_installation {
  dev_overrides {
    "ubiquiti-community/unifi" = "/absolute/path/to/terraform-provider-unifi/.local-bin"
  }
  direct {}
}
```

Run `terraform providers schema -json` and look for `unifi_firewall_policy_ordering` to verify that Terraform loaded the fork. Terraform 1.11 or later is required for write-only arguments.

## Using the upstream release

### Terraform 1.0 and above

You can use the provider via the [Terraform provider registry](https://registry.terraform.io/providers/ubiquiti-community/unifi).
