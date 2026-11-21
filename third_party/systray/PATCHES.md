# Wantastic patches to getlantern/systray v1.2.2

Vendored because Windows closes a tray menu on every click, so a switch or
"Ping all" never showed its result. Upstream has no way to reopen the menu.

- `MenuItem.KeepMenuOpen()`: a click on that item reopens the menu.
- Windows: the menu reopens at the point it last opened (`showMenuAt`,
  `wmReopenMenu` = WM_USER+2), not under the cursor.
- Other platforms: `reopenMenu` is a no-op.

The `example` and `webview_example` directories were removed.
