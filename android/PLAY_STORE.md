# Publishing Wantastic on Google Play

What the app already does for Play, what only the Play Console owner can
do, and the forms filled from what the code actually does. Anything marked
**DRAFT** is wording for the owner to approve, not a statement of fact.

## Done in the app and CI

| Requirement | Where |
| --- | --- |
| Target API 36 (Android 16), required for new apps since 31 Aug 2026 | `app/build.gradle.kts` |
| Native code 16 KB page aligned (Go engine) | `.github/workflows/android.yml` (`max-page-size=16384`) |
| App Bundle (`.aab`) for Play | CI `bundlePlayRelease`, attached to each GitHub release |
| No self-update in the Play build (Device and Network Abuse policy) | flavor `play`: Play In-App Updates only; `REQUEST_INSTALL_PACKAGES` exists only in `src/direct` |
| VPN service declared correctly | `BIND_VPN_SERVICE`, `SUPPORTS_ALWAYS_ON`, foreground type `systemExempted` |
| Notification permission asked in context (first connect), not at launch | `MainActivity.requestTunnel` |
| Edge-to-edge, predictive back, large screens and TV | Compose, `BackHandler`, leanback entry |
| No analytics, ads or crash SDKs | dependencies in `app/build.gradle.kts` |
| Open-source notices, privacy policy, terms, source link in the app | Settings → About |
| Keys and approvals stored encrypted; excluded from backups | `ClaimKey` (EncryptedSharedPreferences), `data_extraction_rules.xml`, `allowBackup=false` |

## Blocker before production

**Account deletion.** Play requires apps that let people create an account
(this app can, natively and in the console) to offer account deletion both
in the app and on the web, and to list the web link in the Data safety
form. The console has no account deletion today (no RPC in the portal
allow-list, no Account section). It needs a portal + hub feature; then add
a "Delete account" row under Settings → Account pointing at it.

## Play Console steps (owner)

1. **App signing.** Enrol in Play App Signing and upload the current key
   (`~/.wantastic/android-signing/wantastic-release.keystore`, alias
   `wantastic`) as the *upload* key. The direct APK stays signed with the
   same key, so both builds can be checked against each other.
2. **Testing track.** New personal developer accounts must run a closed
   test with at least 12 testers for 14 days before production access.
   Upload `wantastic-android-<version>-play.aab` from the GitHub release.
3. **VPN declaration** (App content → VPN service). Core functionality:
   "Wantastic connects this device to the owner's private network
   (WireGuard) so their own devices reach each other; optionally routes
   internet traffic through an exit node the owner chose."
   **DRAFT** — confirm the traffic statement below before submitting.
4. **Foreground service declaration.** Type `systemExempted`, used only by
   the VPN service while a tunnel is active; show the connect flow in the
   video Play asks for.
5. **Data safety** (below). **Content rating** questionnaire: utility, no
   user-generated content shown to others. **Target audience:** 18+.
6. **Store listing:** 512×512 icon, 1024×500 feature graphic, phone and
   tablet screenshots, short and full description, privacy policy URL
   `https://console.wantastic.app/privacy`.

## Data safety form (from the code)

| Data | Collected | Why | Optional |
| --- | --- | --- | --- |
| Email, name | Yes (sign-in, registration) | Account management | No |
| Phone number | Yes (registration, 2FA, password reset by SMS) | Account management, security | No |
| Device name | Yes (claim) | App functionality (names the device in the account) | Can be renamed |
| Device or other IDs | Yes: WireGuard public key; an HMAC-hashed device id | App functionality, security | No |
| Approximate location | Not collected by the app. The server sees the device's public IP as a VPN endpoint. **DRAFT:** decide whether to declare IP-derived country (the console shows endpoint country). | | |
| App activity, crash logs, diagnostics | Not collected (no SDKs) | | |
| Web browsing / traffic | **DRAFT — owner must state:** whether any traffic content or metadata is logged when it passes Wantastic hubs or exit nodes. | | |

- Encrypted in transit: yes (TLS; the console channel is also end-to-end
  encrypted with AES-256-GCM).
- Deletion: devices can be removed in the console; **account deletion is
  the blocker above**.
- Shared with third parties: **DRAFT** — SMS provider (codes), Stripe
  (paid plans only, in the console). Confirm the list.

## Privacy policy: Android / VPN section (**DRAFT**)

> **Wantastic for Android.** The app creates a WireGuard key on your phone;
> the private key never leaves the phone. When you add the phone to your
> account, Wantastic receives its public key, its name and the account it
> belongs to, and assigns it an address in your network. While connected,
> your phone's traffic to your own devices travels encrypted between them,
> through Wantastic hubs only when a direct path is not possible. If you
> choose an exit node, your internet traffic leaves through that device.
> [State what is logged on hubs and exit nodes, and for how long.]
> The app has no advertising or analytics. Signing in uses the same
> account, two-factor and session rules as the console.

The current policy at `/privacy` has no Android or VPN section; add this
(once approved) before submitting the VPN declaration.

## Releasing

Tag `android-vX.Y.Z` on the `android` branch. CI tests, lints, builds
both flavors, makes update patches from the last three releases, and
publishes: the direct APK and `update.json` to
`https://get.wantastic.app/android/`, the Play bundle to the GitHub
release (upload it to the Play track by hand, or add a Play publishing
step once a service account exists).
