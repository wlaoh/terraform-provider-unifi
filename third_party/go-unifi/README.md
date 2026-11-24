# UniFi client used by this provider fork

The runtime package, tests, module files, and license are copied from [go-unifi v1.43.2](https://github.com/ubiquiti-community/go-unifi/tree/v1.43.2), commit `bc2a8ea39376191b81e01425a5a72a9643532c9f`. The provider's root module resolves SDK imports to this directory so fixes apply to standard builds, tests, and releases.

To update the SDK, compare this directory with the previous upstream tag, import the new tag's `unifi/`, `go.mod`, `go.sum`, and `LICENSE`, and reconcile the fork changes. Update the upstream version in the provider's `go.mod` and here. Run `go test ./...` both here and at the provider root. The schema generators live in the upstream SDK repository.
