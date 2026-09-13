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
`stash/providers/proxyplankton.yaml` every six hours. Before enabling it, add
the original subscription URL as a repository secret named
`STASH_SUBSCRIPTION_URL`:

1. GitHub repository → **Settings** → **Secrets and variables** → **Actions**.
2. Create **New repository secret** named `STASH_SUBSCRIPTION_URL`.
3. Paste the subscription URL as its value.
4. In **Actions**, run **Update Stash provider** once to verify the secret.

The provider YAML contains connection credentials so that Stash can download it.
Because this repository is public, anyone with the raw provider URL can use
those nodes. Keep the repository private if that is not acceptable.

## DNS

The initial configuration uses the device's `system` DNS. To use Google DoH,
replace `system` in both DNS lists in `clash_config.yaml` with
`https://dns.google/dns-query` and re-import or update the configuration.
