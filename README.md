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

## Operating notes

- Add only the root Cloud config URL shown above to Stash. Do not import   `stash/providers/proxyplankton.yaml` directly: it is an internal node list   without routing, DNS, or policy groups.
- `clash_config.yaml` is the stable entry point. It provides DNS, direct-route   rules, `AUTO` and `PROXY`, and a bootstrap node so `AUTO` is usable while a   remote provider is loading.
- The Action updates only `stash/providers/proxyplankton.yaml`. A changed   ProxyPlankton subscription therefore normally reaches GitHub within six   hours, then reaches a running Stash profile on its provider refresh interval   (one hour). The root config does not need to change for ordinary node updates.
- The source subscription is stored only as the GitHub Actions secret   `STASH_SUBSCRIPTION_URL`; never put it in this repository or in documentation.
- Repository publishing is performed through the authenticated GitHub browser   session. No personal access token or deploy key is stored in the repository.

Because this repository is public, anyone with the raw provider URL can use
those nodes. Keep the repository private if that is not acceptable.

## DNS

The configuration uses Google DNS over HTTPS (DoH) for all DNS requests.
