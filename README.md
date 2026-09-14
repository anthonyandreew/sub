# Personal VPN configuration

## Active Stash profiles for iOS

- Manual node selection: [VPN_Stash.yaml](https://raw.githubusercontent.com/anthonyandreew/sub/main/VPN_Stash.yaml)
- Automatic lowest-latency node selection: [VPN_Stash_Auto.yaml](https://raw.githubusercontent.com/anthonyandreew/sub/main/VPN_Stash_Auto.yaml)

Both profiles use Google DNS over HTTPS, send the Russian direct-list domains and IP ranges directly, and send all other traffic to the VPN. The manual profile contains only the PROXY group; the auto profile uses AUTO.

## Clients in use

- iOS: Stash is the primary client, including its On-Demand rules. Happ and AmneziaVPN are also retained.
- Android: Happ and AmneziaVPN. No Android-specific Clash/Stash configuration is maintained in this repository.

## Automatic subscription updates

The Update Stash provider GitHub Actions workflow rebuilds stash/providers/proxyplankton.yaml every six hours using the repository secret STASH_SUBSCRIPTION_URL. The source subscription must never be committed to this repository.

Stash refreshes the provider independently; the root profile normally does not need to change when nodes are added or removed from the subscription.

## Repository access

Publishing is performed through the authenticated GitHub browser session. No personal access token or deploy key is stored in this repository.
