# ExtYARA Rule Patterns (per tactic)

Adaptable seed rules. Combine manifest + behavior signals. Tune strings/condition and FP-test against a benign corpus before shipping. Each maps to an Extension ATT&CK technique id.

## Scanning harness note
ExtYARA scans the **unzipped** extension tree. Pipeline: unzip CRX (skip the CRX header/signature block) or XPI → run YARA recursively over `manifest.json` + all `.js/.html/.json/.wasm`. Also parse `manifest.json` separately for structured checks (permission arrays) that raw string matching can't express, and record both signals.

## Execution — EXT-EXEC-001 dynamic injection
```yara
rule EXTYARA_EXEC_001_dynamic_injection {
  meta: technique="EXT-EXEC-001" tactic="Execution" platform="chrome,edge" confidence="medium"
  strings:
    $p = "\"scripting\""
    $a1 = "executeScript"
    $world_main = "\"MAIN\""
  condition: $p and $a1 and $world_main
}
```

## Execution — EXT-EXEC-002 eval/new Function
```yara
rule EXTYARA_EXEC_002_dynamic_eval {
  meta: technique="EXT-EXEC-002" tactic="Execution" platform="chrome,edge,firefox" confidence="low"
  strings: $e1="eval(" $e2="new Function(" $remote="fetch("
  condition: 1 of ($e1,$e2) and $remote
}
```

## Defense Evasion — EXT-DEFEV-004 DNR header/traffic manipulation
```yara
rule EXTYARA_DEFEV_004_dnr_header_hide {
  meta: technique="EXT-DEFEV-004" tactic="Defense Evasion" platform="chrome,edge" confidence="medium"
  strings:
    $m = "declarative_net_request"
    $mh = "modifyHeaders"
    $rm_cookie = "\"cookie\""
    $redir = "regexSubstitution"
  condition: $m and ($mh and $rm_cookie or $redir)
}
```

## Credential Access — EXT-CRED-001 cookie theft
```yara
rule EXTYARA_CRED_001_cookie_theft {
  meta: technique="EXT-CRED-001" tactic="Credential Access" platform="chrome,edge,firefox" confidence="high"
  strings:
    $perm="\"cookies\""
    $host="\"<all_urls>\""
    $api="cookies.getAll"
    $exfil1="fetch(" $exfil2="sendBeacon(" $exfil3="WebSocket("
  condition: $perm and $api and ($host and 1 of ($exfil1,$exfil2,$exfil3))
}
```

## Credential Access — EXT-CRED-003 keystroke/form capture
```yara
rule EXTYARA_CRED_003_input_capture {
  meta: technique="EXT-CRED-003" tactic="Credential Access" platform="chrome,edge,firefox" confidence="medium"
  strings: $k="addEventListener(\"keydown\"" $i="addEventListener(\"input\"" $f="\"password\"" $exfil="fetch("
  condition: 1 of ($k,$i) and $f and $exfil
}
```

## Collection — EXT-COLL-003 screenshot/tab capture
```yara
rule EXTYARA_COLL_003_screen_capture {
  meta: technique="EXT-COLL-003" tactic="Collection" platform="chrome,edge" confidence="medium"
  strings: $a1="captureVisibleTab" $a2="getDisplayMedia" $a3="desktopCapture" $exfil="fetch("
  condition: 1 of ($a1,$a2,$a3) and $exfil
}
```

## C2 — EXT-C2-002 WebSocket C2
```yara
rule EXTYARA_C2_002_websocket_c2 {
  meta: technique="EXT-C2-002" tactic="Command & Control" platform="chrome,edge,firefox" confidence="low"
  strings: $ws="new WebSocket(" $bg="service_worker"
  condition: $ws and $bg
}
```

## Persistence — EXT-PERS-001 self-hosted update
```yara
rule EXTYARA_PERS_001_selfhost_update {
  meta: technique="EXT-PERS-001" tactic="Persistence" platform="chrome,edge" confidence="medium"
  strings: $u="update_url" $g="clients2.google.com"
  condition: $u and not $g
}
```

## Persistence — EXT-PERS-004 native messaging
```yara
rule EXTYARA_PERS_004_native_messaging {
  meta: technique="EXT-PERS-004" tactic="Persistence" platform="chrome,edge,firefox" confidence="medium"
  strings: $p="\"nativeMessaging\"" $a1="connectNative" $a2="sendNativeMessage"
  condition: $p and 1 of ($a1,$a2)
}
```

## Impact — EXT-IMPACT-001 search hijack
```yara
rule EXTYARA_IMPACT_001_search_hijack {
  meta: technique="EXT-IMPACT-001" tactic="Impact" platform="chrome,edge,firefox" confidence="high"
  strings: $o="chrome_settings_overrides" $s="search_provider"
  condition: $o and $s
}
```

## Impact — EXT-IMPACT-004 proxy node
```yara
rule EXTYARA_IMPACT_004_proxy_node {
  meta: technique="EXT-IMPACT-004" tactic="Impact" platform="chrome,edge,firefox" confidence="medium"
  strings: $p="\"proxy\"" $a="proxy.settings.set" $pac="pacScript"
  condition: $p and 1 of ($a,$pac)
}
```

## FP-reduction tips
- Require the **manifest permission** string AND the **API** string AND an **egress/trigger** string.
- Exclude well-known benign bundles via an allowlist of SHA-256 or signing keys.
- Prefer `confidence=low` for single-signal rules; reserve `high` for tight multi-signal combos (search hijack, cookie theft).
