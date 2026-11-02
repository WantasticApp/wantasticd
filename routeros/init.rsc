# Wantastic RouterOS Library v1.3
# Compatible: RouterOS v7.1+ (backup upload requires v7.13+ for /file/read)
#
# Usage:
#   /tool fetch url="https://get.wantastic.app/routeros/init.rsc" mode=https check-certificate=no
#   /import init.rsc
#   :global wantasticDeploy
#   $wantasticDeploy privateKey=... publicKey=... endpoint=... address=... ...
#   $wantasticRemove        (takes everything the deploy added back out)
#
# The deploy is safe to re-run and never fights the router's own setup:
#   - routes: no default route, no duplicate of a prefix the router already
#     routes, overlaps with the router's own networks are reported;
#   - WireGuard listens on 51820, or the next port no other interface uses;
#   - management services (api, api-ssl, ssh, winbox, www, www-ssl) keep the
#     owner's address lists, with the tenant range added; nothing is ever
#     opened to everyone. See docs/routeros.md.
#
# Coding rules (proven the hard way — see memory):
#   - Cleanup ops use :do{} on-error={} so "not found" is silent
#   - Critical ops are NOT wrapped — RouterOS prints its own error and halts
#   - Each critical step has a :put "[deploy] step=X ..." line before it so the
#     last printed step before the halt tells us where it failed
#   - Named function params are read with $name; cannot :set them. To get a
#     mutable copy, do :local mutableX $x at the top of the function body.
#   - Strings containing / = + are passed via :local then ($var) at call sites.

:global wantasticDeploy do={
  :local tag "WANTASTIC-WG"

  :put "[deploy] step=start"

  # Parse the numeric major version. RouterOS returns values such as
  # "7.20.6 (stable)", so comparing the complete string is not reliable.
  :local verStr [/system resource get version]
  :local verDot [:find $verStr "."]
  :if ([:typeof $verDot] = "nil") do={:error "[deploy] FAIL: cannot parse RouterOS version $verStr"}
  :local verMajor [:tonum [:pick $verStr 0 $verDot]]
  :if ($verMajor < 7) do={:error "[deploy] FAIL: RouterOS version $verStr is too old; v7+ required"}
  :put ("[deploy] step=check-version ok version=" . $verStr)

  # Validate required params (using :error halts with a clear message)
  :if ([:len $privateKey] = 0) do={:error "[deploy] FAIL: privateKey required"}
  :if ([:len $publicKey]  = 0) do={:error "[deploy] FAIL: publicKey required"}
  :if ([:len $endpoint]   = 0) do={:error "[deploy] FAIL: endpoint required"}
  :if ([:len $address]    = 0) do={:error "[deploy] FAIL: address required"}
  :if ([:len $allowedIPs] = 0) do={:error "[deploy] FAIL: allowedIPs required"}
  :put "[deploy] step=validate ok"

  # The first WireGuard route is the management subnet used by Wantastic.
  # Resolve it once and reuse the exact prefix for RouterOS service access.
  # /ip service address is an application-level source allowlist; the input
  # firewall rule below remains the network-level protection recommended by
  # MikroTik.
  :local firstSubnet ""
  :foreach net in=[:toarray $allowedIPs] do={
    :if (([:len $firstSubnet] = 0) && ([:len $net] > 0)) do={:set firstSubnet $net}
  }
  :if ([:len $firstSubnet] = 0) do={:error "[deploy] FAIL: allowedIPs has no usable management subnet"}
  :put ("[deploy] step=management-subnet ok subnet=" . $firstSubnet)

  # Parse endpoint host:port
  :local colonPos [:find $endpoint ":" 0]
  :if ([:typeof $colonPos] = "nil") do={:error "[deploy] FAIL: endpoint must be host:port"}
  :local epHost [:pick $endpoint 0 $colonPos]
  :local epPort [:pick $endpoint ($colonPos + 1) [:len $endpoint]]
  :put ("[deploy] step=parse-endpoint host=" . $epHost . " port=" . $epPort)

  # If endpoint is a domain name and this fails, WireGuard cannot resolve it
  # either. Run this only after endpoint validation and parsing.
  # An IP endpoint needs no DNS (RouterOS 7.25 :resolve rejects IP literals).
  :local resolved $epHost
  # A cold DNS cache can time out once on a fresh router; retry, and if it
  # still fails carry on: WireGuard keeps resolving the name by itself.
  :if (([:typeof [:toip $epHost]] != "ip") && ([:typeof [:toip6 $epHost]] != "ip6")) do={
    :set resolved ""
    :local tries 0
    :while (([:len $resolved] = 0) && ($tries < 3)) do={
      :do {:set resolved [:resolve $epHost]} on-error={:delay 2s}
      :set tries ($tries + 1)
    }
    :if ([:len $resolved] = 0) do={
      :put ("[deploy] WARN: cannot resolve " . $epHost . " yet; check the router's DNS (WireGuard will keep trying)")
      :set resolved "pending"
    }
  }
  :put ("[deploy] step=check-connectivity ok resolved-endpoint=" . $resolved)

  # Cleanup old config — on-error swallows "no such item". Order matters:
  # references (firewall rules, routes, addresses, peers) before the interface.
  :do {
    :foreach r in=[/ip/firewall/filter find where comment=$tag] do={/ip/firewall/filter remove $r}
    :foreach r in=[/ip/firewall/nat    find where comment=$tag] do={/ip/firewall/nat    remove $r}
    :foreach r in=[/ip/route           find where comment=$tag] do={/ip/route           remove $r}
    :do {:foreach r in=[/ipv6/route find where comment=$tag] do={/ipv6/route remove $r}} on-error={}
    :foreach a in=[/ip/address         find where comment=$tag] do={/ip/address         remove $a}
    :foreach p in=[/interface/wireguard/peers find where interface="wg-wantastic"] do={/interface/wireguard/peers remove $p}
    /interface/wireguard remove [find where name="wg-wantastic"]
  } on-error={}
  :put "[deploy] step=cleanup ok"

  # Defaults for optional parameters.
  :local useMtu 1420
  :if ([:len $mtu] > 0) do={:set useMtu $mtu}
  :local useKeepalive "25s"
  :if ([:len $keepalive] > 0) do={:set useKeepalive $keepalive}

  # Another WireGuard interface may already listen on 51820 (a second VPN):
  # take the next free port instead of failing.
  :local listenPort 51820
  :while ([:len [/interface/wireguard find where listen-port=$listenPort]] > 0) do={:set listenPort ($listenPort + 1)}
  :local listenPortText [:tostr $listenPort]
  :put ("[deploy] step=listen-port ok port=" . $listenPortText)

  # Critical: WireGuard interface. Not wrapped — if WireGuard package is
  # missing or another interface owns the name, RouterOS prints the error
  # right after this :put and the script halts there.
  :put "[deploy] step=create-wg-iface attempting"
  /interface/wireguard add name=wg-wantastic listen-port=$listenPort mtu=$useMtu private-key=$privateKey comment=$tag
  :put "[deploy] step=create-wg-iface ok"

  :put "[deploy] step=create-wg-peer attempting"
  /interface/wireguard/peers add interface=wg-wantastic public-key=$publicKey endpoint-address=$epHost endpoint-port=$epPort allowed-address=$allowedIPs persistent-keepalive=$useKeepalive comment=$tag
  :put "[deploy] step=create-wg-peer ok"

  :put "[deploy] step=add-address attempting"
  /ip/address add address=$address interface=wg-wantastic comment=$tag
  :put "[deploy] step=add-address ok"
  # Let the connected route of the new address appear, so the route check
  # below sees that its network is already reachable.
  :delay 1s

  # Routes for the tenant networks, added only where they cannot take traffic
  # away from the router's own routing:
  #   - never a default route (0.0.0.0/0, ::/0): Internet stays on the WAN;
  #   - never a second route for a prefix the router already routes (a static
  #     route, another VPN, a connected LAN): the owner's route is kept and
  #     the conflict is reported;
  #   - a tenant prefix that contains one of the router's own networks is
  #     added (the longer, existing prefix still wins for its addresses) and
  #     the overlap is reported.
  :foreach net in=[:toarray $allowedIPs] do={
    :local dst [:tostr $net]
    :local v6 ([:typeof [:find $dst ":"]] != "nil")
    :if (($dst = "0.0.0.0/0") || ($dst = "::/0")) do={
      :put ("[deploy] step=route skipped dst=" . $dst . " reason=default-route")
    } else={
      :if ($dst != $address) do={
        # Routes through the tunnel already (the connected route of our own
        # address) need nothing; a route of the owner's for the same prefix
        # is kept and reported.
        :local mine ""
        :local others ""
        :if ($v6) do={
          :do {
            :set mine [/ipv6/route find where dst-address=$dst && gateway="wg-wantastic"]
            :set others [/ipv6/route find where dst-address=$dst && gateway!="wg-wantastic"]
          } on-error={}
        } else={
          :set mine [/ip/route find where dst-address=$dst && gateway="wg-wantastic"]
          :set others [/ip/route find where dst-address=$dst && gateway!="wg-wantastic"]
        }
        :if ([:len $others] > 0) do={
          :put ("[deploy] WARN: route " . $dst . " already exists on this router; kept the existing route")
          :log warning ("WANTASTIC-WG: route " . $dst . " already exists; not added")
        } else={:if ([:len $mine] > 0) do={
          :put ("[deploy] step=route connected dst=" . $dst)
        } else={
          :if ($v6) do={
            :do {/ipv6/route add dst-address=$dst gateway=wg-wantastic comment=$tag} on-error={:put ("[deploy] WARN: IPv6 route " . $dst . " not added")}
          } else={
            /ip/route add dst-address=$dst gateway=wg-wantastic comment=$tag
            :local overlaps 0
            :do {
              :set overlaps [:len [/ip/route find where (dst-address in $dst) && (comment!=$tag) && (gateway!="wg-wantastic")]]
            } on-error={}
            :if ($overlaps > 0) do={
              :put ("[deploy] WARN: " . $overlaps . " of this router's routes are inside " . $dst . "; they stay preferred for their addresses")
            }
          }
          :put ("[deploy] step=route added dst=" . $dst)
        }}
      }
    }
  }
  :put "[deploy] step=routes ok"

  # Required firewall rules — check first, install if missing, skip if present.
  # Each rule is matched by functional shape (chain + match + action), not by
  # comment, so an existing equivalent rule under any comment is honoured and
  # we don't create a duplicate. Cleanup above removed our own tagged rules,
  # so any survivor here belongs to the user.
  #
  # Placement must be SAFE. We want our rules at the top of their respective
  # chains so they cannot be shadowed by later accept/drop logic, but
  # `place-before=0` is not safe on fresh routers because an empty chain/table
  # has no item 0 and RouterOS halts with "no such item". So we first capture
  # the first existing rule in each target chain and only use `place-before`
  # when that anchor actually exists; otherwise we add the first rule plain.
  #
  #   1. input UDP 51820 — controller can complete the WireGuard handshake
  #   2. input from wg-wantastic — controller can reach router services (SSH,
  #      Winbox, API, web) over the tunnel
  #   3. forward in/out wg-wantastic — tunnelled traffic can transit
  #   4. nat srcnat masquerade — outgoing tunnel packets get a usable src IP
  :put "[deploy] step=firewall checking"
  # Anchors skip dynamic rules (the fasttrack counter rule RouterOS shows at
  # the top of forward): nothing can be placed before those.
  :local inputAnchor ""
  :foreach r in=[/ip/firewall/filter find where chain=input && dynamic=no] do={
    :if ([:len $inputAnchor] = 0) do={:set inputAnchor $r}
  }
  :local forwardAnchor ""
  :foreach r in=[/ip/firewall/filter find where chain=forward && dynamic=no] do={
    :if ([:len $forwardAnchor] = 0) do={:set forwardAnchor $r}
  }
  :local srcnatAnchor ""
  :foreach r in=[/ip/firewall/nat find where chain=srcnat && dynamic=no] do={
    :if ([:len $srcnatAnchor] = 0) do={:set srcnatAnchor $r}
  }

  :local inputUDP [/ip/firewall/filter find where chain=input protocol=udp dst-port=$listenPortText action=accept]
  :if ([:len $inputUDP] = 0) do={
    :if ([:len $inputAnchor] > 0) do={
      /ip/firewall/filter add chain=input protocol=udp dst-port=$listenPortText action=accept place-before=$inputAnchor comment=$tag
    } else={
      /ip/firewall/filter add chain=input protocol=udp dst-port=$listenPortText action=accept comment=$tag
    }
    :put ("[deploy] step=firewall input-udp" . $listenPortText . " installed")
  } else={
    :local existing ""
    :foreach r in=$inputUDP do={:if ([:len $existing] = 0) do={:set existing $r}}
    :if (([:len $inputAnchor] > 0) && ($existing != $inputAnchor)) do={
      /ip/firewall/filter move $existing destination=$inputAnchor
    }
    :put ("[deploy] step=firewall input-udp" . $listenPortText . " ensured-at-top")
  }

  :local inputWG [/ip/firewall/filter find where chain=input in-interface=wg-wantastic action=accept]
  :if ([:len $inputWG] = 0) do={
    :if ([:len $inputAnchor] > 0) do={
      /ip/firewall/filter add chain=input in-interface=wg-wantastic action=accept place-before=$inputAnchor comment=$tag
    } else={
      /ip/firewall/filter add chain=input in-interface=wg-wantastic action=accept comment=$tag
    }
    :put "[deploy] step=firewall input-wg installed"
  } else={
    :local existing ""
    :foreach r in=$inputWG do={:if ([:len $existing] = 0) do={:set existing $r}}
    :if (([:len $inputAnchor] > 0) && ($existing != $inputAnchor)) do={
      /ip/firewall/filter move $existing destination=$inputAnchor
    }
    :put "[deploy] step=firewall input-wg ensured-at-top"
  }

  :local forwardInWG [/ip/firewall/filter find where chain=forward in-interface=wg-wantastic action=accept]
  :if ([:len $forwardInWG] = 0) do={
    :if ([:len $forwardAnchor] > 0) do={
      /ip/firewall/filter add chain=forward in-interface=wg-wantastic action=accept place-before=$forwardAnchor comment=$tag
    } else={
      /ip/firewall/filter add chain=forward in-interface=wg-wantastic action=accept comment=$tag
    }
    :put "[deploy] step=firewall forward-in-wg installed"
  } else={
    :local existing ""
    :foreach r in=$forwardInWG do={:if ([:len $existing] = 0) do={:set existing $r}}
    :if (([:len $forwardAnchor] > 0) && ($existing != $forwardAnchor)) do={
      /ip/firewall/filter move $existing destination=$forwardAnchor
    }
    :put "[deploy] step=firewall forward-in-wg ensured-at-top"
  }

  :local forwardOutWG [/ip/firewall/filter find where chain=forward out-interface=wg-wantastic action=accept]
  :if ([:len $forwardOutWG] = 0) do={
    :if ([:len $forwardAnchor] > 0) do={
      /ip/firewall/filter add chain=forward out-interface=wg-wantastic action=accept place-before=$forwardAnchor comment=$tag
    } else={
      /ip/firewall/filter add chain=forward out-interface=wg-wantastic action=accept comment=$tag
    }
    :put "[deploy] step=firewall forward-out-wg installed"
  } else={
    :local existing ""
    :foreach r in=$forwardOutWG do={:if ([:len $existing] = 0) do={:set existing $r}}
    :if (([:len $forwardAnchor] > 0) && ($existing != $forwardAnchor)) do={
      /ip/firewall/filter move $existing destination=$forwardAnchor
    }
    :put "[deploy] step=firewall forward-out-wg ensured-at-top"
  }

  :local srcnatWG [/ip/firewall/nat find where chain=srcnat out-interface=wg-wantastic action=masquerade]
  :if ([:len $srcnatWG] = 0) do={
    :if ([:len $srcnatAnchor] > 0) do={
      /ip/firewall/nat add chain=srcnat out-interface=wg-wantastic action=masquerade place-before=$srcnatAnchor comment=$tag
    } else={
      /ip/firewall/nat add chain=srcnat out-interface=wg-wantastic action=masquerade comment=$tag
    }
    :put "[deploy] step=firewall srcnat-wg installed"
  } else={
    :local existing ""
    :foreach r in=$srcnatWG do={:if ([:len $existing] = 0) do={:set existing $r}}
    :if (([:len $srcnatAnchor] > 0) && ($existing != $srcnatAnchor)) do={
      /ip/firewall/nat move $existing destination=$srcnatAnchor
    }
    :put "[deploy] step=firewall srcnat-wg ensured-at-top"
  }

  :put "[deploy] step=firewall ok"

  # Management services must answer the tenant range, without being opened
  # to anyone else and without dropping the owner's own access. They are
  # built-in /ip service entries: modified with `set`, never added, and the
  # address list and enabled state are set together so a service is never
  # briefly enabled without its source restriction.
  #   - owner restricted it (non-empty list): the tenant range is added;
  #   - disabled: enabled for the tenant range only;
  #   - unrestricted: api and api-ssl (the console's data channel) become
  #     tenant-only; ssh, winbox, www and www-ssl stay as the owner set them.
  :put ("[deploy] step=services configuring tenant-range=" . $firstSubnet)
  :foreach svc in={"api";"api-ssl";"ssh";"winbox";"www";"www-ssl"} do={
    # RouterOS 7.25 also lists live sessions as dynamic entries of the same
    # name (older v7 has no "dynamic" property here, so it cannot go in the
    # find), and calls the address list available-from (reading the old
    # "address" name returns nothing there); older v7 only has "address".
    :local id ""
    :foreach i in=[/ip/service find where name=$svc] do={
      :local dyn false
      :do {:set dyn [/ip/service get $i dynamic]} on-error={}
      :if (([:len $id] = 0) && ($dyn != true)) do={:set id $i}
    }
    :if ([:len $id] > 0) do={
      :local addrs ""
      :do {:set addrs [/ip/service get $id available-from]} on-error={}
      :if ([:len $addrs] = 0) do={:do {:set addrs [/ip/service get $id address]} on-error={}}
      :local list ""
      :foreach a in=$addrs do={:if ([:len [:tostr $a]] > 0) do={:set list ($list . [:tostr $a] . ",")}}
      :local isAPI (($svc = "api") || ($svc = "api-ssl"))
      :if ([/ip/service get $id disabled] || ($isAPI && ([:len $list] = 0))) do={
        /ip/service set $id address=$firstSubnet disabled=no
        :put ("[deploy] step=service " . $svc . " enabled-for-tenant")
      } else={
        :if (([:len $list] > 0) && ([:typeof [:find ("," . $list) ("," . $firstSubnet . ",")]] = "nil")) do={
          /ip/service set $id address=($list . $firstSubnet)
          :put ("[deploy] step=service " . $svc . " tenant-added")
        } else={
          :put ("[deploy] step=service " . $svc . " ok")
        }
      }
    }
  }
  :put "[deploy] step=services ok"

  # Save config globals for recovery (manual: run $wantasticRestore later)
  :global wantasticCfg ("$privateKey|$publicKey|$epHost:$epPort|$address|$allowedIPs|$useMtu|$useKeepalive")
  :if ([:len $backupToken] > 0) do={:global wantasticToken $backupToken}
  :if ([:len $peerName]    > 0) do={:global wantasticName  $peerName}
  :if ([:len $hookURL]     > 0) do={:global wantasticHookURL $hookURL}
  # Native .backup files are AES-encrypted. A dedicated password may be passed
  # as backupPassword=. For generated onboarding commands, fall back to the
  # 256-bit peer upload token so backups are never written unencrypted.
  :local effectiveBackupPassword ""
  :if ([:len $backupPassword] > 0) do={:set effectiveBackupPassword $backupPassword}
  :if (([:len $effectiveBackupPassword] = 0) && ([:len $backupToken] > 0)) do={
    :set effectiveBackupPassword $backupToken
  }
  :if ([:len $effectiveBackupPassword] > 0) do={
    :global wantasticBackupPassword $effectiveBackupPassword
  }
  :put "[deploy] step=save-globals ok"

  :put "[deploy] step=done — configuration applied"
  :log info "WANTASTIC-WG: deployed successfully"
}

:global wantasticBackup do={
  :global wantasticToken
  :global wantasticName
  :global wantasticHookURL
  :global wantasticBackupPassword

  :put "[backup] step=start"

  :if ([:len $wantasticToken] = 0) do={
    :put "[backup] FAIL: no backup token (deploy was not called with backupToken=)"
    :return false
  }
  :put ("[backup] step=token len=" . [:len $wantasticToken])

  # Defaults & overrides — :local then :set against the local (allowed)
  :local bName "mikrotik"
  :if ([:len $wantasticName] > 0) do={:set bName $wantasticName}
  :put ("[backup] step=name value=" . $bName)

  :local baseURL "https://console.wantastic.app/hooks/backup"
  :if ([:len $wantasticHookURL] > 0) do={:set baseURL $wantasticHookURL}
  :put ("[backup] step=baseURL value=" . $baseURL)

  # Send onboarding identity independently before doing the potentially large
  # export. This mirrors ISPApp's proven small JSON/plain-data POST pattern:
  # HTTP request data is supplied with http-data, never src-path.
  :local rbModel ""
  :local rbSerial ""
  :local rbFirmware ""
  :local rbWGPublicKey ""
  :do {:set rbModel [/system routerboard get model]} on-error={}
  :do {:set rbSerial [/system routerboard get serial-number]} on-error={}
  :do {:set rbFirmware [/system routerboard get current-firmware]} on-error={}
  :do {
    :local rbWGID [/interface/wireguard find where name="wg-wantastic"]
    :if ([:len $rbWGID] > 0) do={
      :set rbWGPublicKey [/interface/wireguard get $rbWGID public-key]
    }
  } on-error={}
  :if ([:len $rbModel] = 0) do={:set rbModel [/system resource get board-name]}
  :if ([:len $rbWGPublicKey] = 0) do={
    :put "[backup] FAIL: cannot read wg-wantastic public key for peer-bound onboarding"
    :return false
  }
  # Keep this payload deliberately simple for early RouterOS v7 releases:
  # no :serialize, :convert, file reads, or other newer scripting helpers.
  :local devicePayload ("identity=" . [/system identity get name] . "\nmodel=" . $rbModel . "\nserial=" . $rbSerial . "\nsoftware_version=" . [/system resource get version] . "\nhardware_version=" . $rbFirmware . "\nwireguard_public_key=" . $rbWGPublicKey)
  :local infoUploaded false
  :local infoAttempt 1
  :local infoURL ($baseURL . "?type=device-info")
  :local authTextHeader ("Authorization:Bearer " . $wantasticToken . ",Content-Type:text/plain")
  :while (($infoAttempt <= 3) && ($infoUploaded = false)) do={
    :do {
      /tool fetch http-method=post http-header-field=$authTextHeader http-data=$devicePayload url=$infoURL output=none check-certificate=no
      :set infoUploaded true
    } on-error={
      :put ("[backup] WARN: device-info attempt=" . $infoAttempt . " failed")
      :delay 2s
    }
    :set infoAttempt ($infoAttempt + 1)
  }
  :if ($infoUploaded = false) do={
    :put "[backup] FAIL: separate device information upload failed"
    :log warning "WANTASTIC-WG: device information upload failed"
    :return false
  }
  :put "[backup] step=device-info ok"

  # RouterOS HTTP fetch cannot upload a local file with src-path. That property
  # is an FTP/SFTP file-transfer option. RouterOS v7.13 introduced /file/read,
  # which lets us read a large export in bounded chunks and send each chunk as
  # HTTP http-data without ever loading the complete backup into one variable.
  :local versionText [/system resource get version]
  :local firstDot [:find $versionText "."]
  :if ([:typeof $firstDot] = "nil") do={
    :put ("[backup] FAIL: cannot parse RouterOS version " . $versionText)
    :return false
  }
  :local versionTail [:pick $versionText ($firstDot + 1) [:len $versionText]]
  :local minorEnd [:find $versionTail "."]
  :if ([:typeof $minorEnd] = "nil") do={:set minorEnd [:find $versionTail " "]}
  :if ([:typeof $minorEnd] = "nil") do={:set minorEnd [:len $versionTail]}
  :local minorText [:pick $versionTail 0 $minorEnd]
  :local versionMajor [:tonum [:pick $versionText 0 $firstDot]]
  :local versionMinor [:tonum $minorText]
  :if (($versionMajor < 7) || (($versionMajor = 7) && ($versionMinor < 13))) do={
    :put ("[backup] FAIL: RouterOS " . $versionText . " cannot safely chunk large HTTP uploads; upgrade to v7.13+")
    :return false
  }

  :local exportFile "wantastic-export.rsc"
  :do {/file remove [find where name=$exportFile]} on-error={}
  :put "[backup] step=export attempting"
  /export terse show-sensitive file=wantastic-export
  :delay 1s

  :local exportID [/file find where name=$exportFile]
  :if ([:len $exportID] = 0) do={
    :put "[backup] FAIL: export file was not created"
    :return false
  }
  :local exportSize [/file get $exportID size]
  :if ($exportSize = 0) do={
    :put "[backup] FAIL: export file is empty"
    :do {/file remove $exportID} on-error={}
    :return false
  }
  :if ($exportSize > 52428800) do={
    :put ("[backup] FAIL: export is larger than the 50 MiB upload limit bytes=" . $exportSize)
    :do {/file remove $exportID} on-error={}
    :return false
  }
  :put ("[backup] step=export ok bytes=" . $exportSize)

  :local chunkSize 32768
  :local chunkTotal ($exportSize / $chunkSize)
  :if (($exportSize % $chunkSize) > 0) do={:set chunkTotal ($chunkTotal + 1)}
  :if ($chunkTotal > 2048) do={
    :put ("[backup] FAIL: export requires " . $chunkTotal . " chunks; maximum is 2048")
    :do {/file remove $exportID} on-error={}
    :return false
  }

  :local uploadID ($rbSerial . "-" . [/system clock get time])
  :if ([:len $rbSerial] = 0) do={:set uploadID ("routeros-" . [/system clock get time])}
  :local chunkIndex 0
  :local chunkOffset 0
  :while ($chunkIndex < $chunkTotal) do={
    :local bytesRemaining ($exportSize - $chunkOffset)
    :local bytesToRead $chunkSize
    :if ($bytesRemaining < $chunkSize) do={:set bytesToRead $bytesRemaining}

    :local readOK false
    :local chunkData ""
    :do {
      :set chunkData (([/file/read file=$exportFile offset=$chunkOffset chunk-size=$bytesToRead as-value])->"data")
      :set readOK true
    } on-error={
      :put ("[backup] FAIL: cannot read chunk=" . $chunkIndex . " offset=" . $chunkOffset)
    }
    :if (($readOK = false) || ([:len $chunkData] = 0)) do={
      :do {/file remove $exportID} on-error={}
      :return false
    }

    :local partURL ($baseURL . "?filename=wantastic-export.rsc&upload_id=" . $uploadID . "&chunk_index=" . $chunkIndex . "&chunk_total=" . $chunkTotal)
    :local uploaded false
    :local attempt 1
    :while (($attempt <= 3) && ($uploaded = false)) do={
      :do {
        /tool fetch http-method=post http-header-field=$authTextHeader http-data=$chunkData url=$partURL output=none check-certificate=no
        :set uploaded true
      } on-error={
        :put ("[backup] WARN: chunk=" . $chunkIndex . "/" . $chunkTotal . " attempt=" . $attempt . " failed")
        :delay 2s
      }
      :set attempt ($attempt + 1)
    }
    :if ($uploaded = false) do={
      :put ("[backup] FAIL: upload failed for chunk=" . $chunkIndex)
      :do {/file remove $exportID} on-error={}
      :return false
    }
    :put ("[backup] step=upload chunk=" . ($chunkIndex + 1) . "/" . $chunkTotal . " bytes=" . [:len $chunkData])
    :set chunkOffset ($chunkOffset + $bytesToRead)
    :set chunkIndex ($chunkIndex + 1)
  }

  :put "[backup] step=upload all-chunks ok"
  :do {/file remove $exportID} on-error={}

  # Native RouterOS backups contain arbitrary bytes. Never pass those bytes
  # directly to HTTP http-data: encode every /file/read chunk independently,
  # and let the hook decode it before durable assembly.
  :if ([:len $wantasticBackupPassword] = 0) do={
    :put "[backup] FAIL: no native backup encryption password"
    :return false
  }
  :local nativeBase "wantastic-native"
  :local nativeFile ($nativeBase . ".backup")
  :do {/file remove [find where name=$nativeFile]} on-error={}
  :put "[backup] step=native-backup attempting"
  /system/backup/save encryption=aes-sha256 name=$nativeBase password=$wantasticBackupPassword
  :delay 1s

  :local nativeID [/file find where name=$nativeFile]
  :if ([:len $nativeID] = 0) do={
    :put "[backup] FAIL: native backup file was not created"
    :return false
  }
  :local nativeSize [/file get $nativeID size]
  :if (($nativeSize = 0) || ($nativeSize > 52428800)) do={
    :put ("[backup] FAIL: invalid native backup size bytes=" . $nativeSize)
    :do {/file remove $nativeID} on-error={}
    :return false
  }

  # /file/read permits 32 KiB. Base64 expands that to about 43 KiB, still
  # safely below RouterOS fetch's 64 KiB HTTP-data ceiling.
  :local nativeChunkSize 32768
  :local nativeChunkTotal ($nativeSize / $nativeChunkSize)
  :if (($nativeSize % $nativeChunkSize) > 0) do={:set nativeChunkTotal ($nativeChunkTotal + 1)}
  :if ($nativeChunkTotal > 2048) do={
    :put ("[backup] FAIL: native backup requires " . $nativeChunkTotal . " chunks; maximum is 2048")
    :do {/file remove $nativeID} on-error={}
    :return false
  }

  :local nativeUploadID ($uploadID . "-binary")
  :local nativeChunkIndex 0
  :local nativeOffset 0
  :while ($nativeChunkIndex < $nativeChunkTotal) do={
    :local nativeRemaining ($nativeSize - $nativeOffset)
    :local nativeReadSize $nativeChunkSize
    :if ($nativeRemaining < $nativeChunkSize) do={:set nativeReadSize $nativeRemaining}

    :local nativeData ""
    :do {
      :set nativeData (([/file/read file=$nativeFile offset=$nativeOffset chunk-size=$nativeReadSize as-value])->"data")
    } on-error={
      :put ("[backup] FAIL: cannot read native chunk=" . $nativeChunkIndex . " offset=" . $nativeOffset)
      :do {/file remove $nativeID} on-error={}
      :return false
    }
    :if ([:len $nativeData] = 0) do={
      :put ("[backup] FAIL: native chunk=" . $nativeChunkIndex . " is empty")
      :do {/file remove $nativeID} on-error={}
      :return false
    }
    :local encodedNative [:convert $nativeData to=base64]
    :local nativeURL ($baseURL . "?filename=wantastic-native.backup&artifact=binary&encoding=base64&upload_id=" . $nativeUploadID . "&chunk_index=" . $nativeChunkIndex . "&chunk_total=" . $nativeChunkTotal)
    :local nativeUploaded false
    :local nativeAttempt 1
    :while (($nativeAttempt <= 3) && ($nativeUploaded = false)) do={
      :do {
        /tool fetch http-method=post http-header-field=$authTextHeader http-data=$encodedNative url=$nativeURL output=none check-certificate=no
        :set nativeUploaded true
      } on-error={
        :put ("[backup] WARN: native chunk=" . $nativeChunkIndex . "/" . $nativeChunkTotal . " attempt=" . $nativeAttempt . " failed")
        :delay 2s
      }
      :set nativeAttempt ($nativeAttempt + 1)
    }
    :if ($nativeUploaded = false) do={
      :put ("[backup] FAIL: native upload failed for chunk=" . $nativeChunkIndex)
      :do {/file remove $nativeID} on-error={}
      :return false
    }
    :put ("[backup] step=native-upload chunk=" . ($nativeChunkIndex + 1) . "/" . $nativeChunkTotal . " raw-bytes=" . [:len $nativeData])
    :set nativeOffset ($nativeOffset + $nativeReadSize)
    :set nativeChunkIndex ($nativeChunkIndex + 1)
  }

  :do {/file remove $nativeID} on-error={}
  :put "[backup] step=native-upload all-chunks ok"
  :log info "WANTASTIC-WG: export and native backup uploaded"
  :put "[backup] step=done"
  :return true
}

:global wantasticRestore do={
  :global wantasticCfg
  :global wantasticToken
  :global wantasticName
  :global wantasticBackupPassword
  :global wantasticDeploy

  :if ([:len $wantasticCfg] = 0) do={
    :put "[restore] FAIL: no saved config (deploy must run first)"
    :return false
  }
  :put "[restore] step=start"

  :local cfg $wantasticCfg
  :local vals [:toarray ""]
  :local i 0
  :while ([:typeof [:find $cfg "|" 0]] != "nil") do={
    :local pos [:find $cfg "|" 0]
    :set ($vals->$i) [:pick $cfg 0 $pos]
    :set cfg [:pick $cfg ($pos + 1) [:len $cfg]]
    :set i ($i + 1)
  }
  :set ($vals->$i) $cfg

  :if ($i < 4) do={
    :put "[restore] FAIL: saved config string is incomplete"
    :return false
  }

  $wantasticDeploy privateKey=($vals->0) publicKey=($vals->1) endpoint=($vals->2) address=($vals->3) allowedIPs=($vals->4) mtu=($vals->5) keepalive=($vals->6) backupToken=($wantasticToken) backupPassword=($wantasticBackupPassword) peerName=($wantasticName)
  :put "[restore] step=done"
}

:global wantasticRemove do={
  :local tag "WANTASTIC-WG"
  :global wantasticCfg
  :put "[remove] step=start"

  # The tenant range is the first allowed network of the saved deploy.
  :local firstSubnet ""
  :if ([:len $wantasticCfg] > 0) do={
    :local cfg $wantasticCfg
    :local field 0
    :while (($field < 4) && ([:typeof [:find $cfg "|"]] != "nil")) do={
      :set cfg [:pick $cfg ([:find $cfg "|"] + 1) [:len $cfg]]
      :set field ($field + 1)
    }
    :local nets $cfg
    :if ([:typeof [:find $nets "|"]] != "nil") do={:set nets [:pick $nets 0 [:find $nets "|"]]}
    :foreach net in=[:toarray $nets] do={
      :if (([:len $firstSubnet] = 0) && ([:len $net] > 0)) do={:set firstSubnet [:tostr $net]}
    }
  }

  # After a reboot the saved deploy is gone (globals do not persist): use
  # the network of the tunnel address the deploy tagged instead.
  :if ([:len $firstSubnet] = 0) do={
    :do {
      :local addrID [/ip/address find where comment=$tag]
      :if ([:len $addrID] > 0) do={
        :local a [/ip/address get ($addrID->0) address]
        :set firstSubnet ([/ip/address get ($addrID->0) network] . [:pick $a [:find $a "/"] [:len $a]])
      }
    } on-error={}
  }

  # Take the tenant range back out of the service lists. A list that would
  # become empty would mean "allow from anywhere", so that service is
  # disabled instead.
  :if ([:len $firstSubnet] > 0) do={
    :foreach svc in={"api";"api-ssl";"ssh";"winbox";"www";"www-ssl"} do={
      :local id ""
      :foreach i in=[/ip/service find where name=$svc] do={
        :local dyn false
        :do {:set dyn [/ip/service get $i dynamic]} on-error={}
        :if (([:len $id] = 0) && ($dyn != true)) do={:set id $i}
      }
      :if ([:len $id] > 0) do={
        :local addrs ""
        :do {:set addrs [/ip/service get $id available-from]} on-error={}
      :if ([:len $addrs] = 0) do={:do {:set addrs [/ip/service get $id address]} on-error={}}
        :local kept ""
        :local had false
        :foreach a in=$addrs do={
          :if ([:tostr $a] = $firstSubnet) do={:set had true} else={:set kept ($kept . [:tostr $a] . ",")}
        }
        :if ($had) do={
          :if ([:len $kept] = 0) do={
            /ip/service set $id disabled=yes
            :put ("[remove] step=service " . $svc . " disabled")
          } else={
            /ip/service set $id address=[:pick $kept 0 ([:len $kept] - 1)]
            :put ("[remove] step=service " . $svc . " tenant-removed")
          }
        }
      }
    }
  }

  :do {
    :foreach r in=[/ip/firewall/filter find where comment=$tag] do={/ip/firewall/filter remove $r}
    :foreach r in=[/ip/firewall/nat    find where comment=$tag] do={/ip/firewall/nat    remove $r}
    :foreach r in=[/ip/route           find where comment=$tag] do={/ip/route           remove $r}
    :do {:foreach r in=[/ipv6/route find where comment=$tag] do={/ipv6/route remove $r}} on-error={}
    :foreach a in=[/ip/address         find where comment=$tag] do={/ip/address         remove $a}
    :foreach p in=[/interface/wireguard/peers find where interface="wg-wantastic"] do={/interface/wireguard/peers remove $p}
    /interface/wireguard remove [find where name="wg-wantastic"]
  } on-error={}
  :set wantasticCfg ""
  :put "[remove] step=done"
  :log info "WANTASTIC-WG: removed"
}

:put "Wantastic RouterOS Library loaded (v1.3)"
