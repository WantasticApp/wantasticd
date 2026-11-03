# Download links (for the landing page)

These URLs never change. Every release overwrites the files behind them, so a
download button that links here always gets the newest version; nothing on the
landing page needs updating when we ship.

| Platform | Button | URL |
| --- | --- | --- |
| macOS (Apple silicon and Intel) | Download for Mac | `https://get.wantastic.app/latest/wantastic-macos.pkg` |
| Windows (x64) | Download for Windows | `https://get.wantastic.app/latest/wantastic-setup-windows-amd64.exe` |
| Windows (ARM) | Windows on ARM | `https://get.wantastic.app/latest/wantastic-setup-windows-arm64.exe` |
| Android | Download APK | `https://get.wantastic.app/android/latest/wantastic-android.apk` |
| Linux, routers | Copy command | `curl -fsSL https://get.wantastic.app/install.sh \| sudo sh` |
| macOS (terminal) | Copy command | `curl -fsSL https://get.wantastic.app/install.sh \| sudo sh` |
| Windows (PowerShell, admin) | Copy command | `irm https://get.wantastic.app/install.ps1 \| iex` |

Plain archives, for people who install by hand:
`https://get.wantastic.app/latest/wantasticd-<os>-<arch>.tar.gz` (linux, darwin)
and `https://get.wantastic.app/latest/wantasticd-windows-<arch>.zip`.

## Showing the version

- Desktop and Linux agent: `https://get.wantastic.app/latest` is a text file
  like `v1.0.71+abc1234`. Show the part before `+`.
- Android: `https://get.wantastic.app/android/latest/version` is a text file
  like `0.4.0`.

Both are uploaded last in a release, after every file they describe is live,
so a version read from them always matches the files above.

The download host may cache files for a while after a release. To skip the
cache, read the version first and add it to the link:
`https://get.wantastic.app/latest/wantastic-macos.pkg?v=v1.0.71%2Babc1234`.

## Older versions

Every release stays at a versioned path:
`https://get.wantastic.app/v1.0.70/wantastic-macos.pkg` and
`https://get.wantastic.app/android/0.4.0/wantastic-android-0.4.0.apk`. Release
notes are on the GitHub releases page.

## Notes for the page

- The Mac installer is not signed by Apple yet. A Mac opened from a browser
  download shows "can't be opened"; the fix is System Settings → Privacy &
  Security → Open Anyway. The `curl` command avoids this.
- Android: the APK updates itself after the first install. People must allow
  "Install unknown apps" for their browser once.
- Where the files come from: `.github/workflows/release.yml` (agent, macOS,
  Linux; Windows through `windows.yml`) and `.github/workflows/android.yml`
  (tags `android-v*`) upload them to the R2 bucket behind get.wantastic.app.
