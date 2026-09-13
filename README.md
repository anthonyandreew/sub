# Stash cloud configuration

Import this configuration into Stash:

```text
https://raw.githubusercontent.com/anthonyandreew/sub/main/clash_config.yaml
```

It sends domains and IP ranges from `russia_direct.txt` directly and routes all
other traffic through the `PROXY` group. `PROXY` lets you choose `AUTO`, any
individual subscription node, or `DIRECT` from the Stash UI.

## Updating the subscription

The `Update Stash provider` GitHub Actions workflow rebuilds
`stash/providers/proxyplankton.yaml` every six hours. The subscription URL is
already stored as the `STASH_SUBSCRIPTION_URL` repository secret and the first
workflow run completed successfully.

The provider YAML contains connection credentials so that Stash can download it.
Because this repository is public, anyone with the raw provider URL can use
those nodes. Keep the repository private if that is not acceptable.

## DNS

The configuration uses Google DNS over HTTPS (DoH) for all DNS requests.
