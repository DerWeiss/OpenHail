# REA Analysis: New Outlook (Microsoft.OutlookForWindows 1.2025.1007.400)

**Purpose:** interop research for an open-source mail client. Facts about a locally
installed program on an owned machine. No proprietary code is reproduced here.

**Tooling:** REA 6.9.0 (Ghidra 12.2 backend), run 2026-11-14.
**Authority:** `OPERATING_OPINION_NO_CAPTURE` — observations are recorded, not inferred claims.

---

## Artifacts analyzed

| File | Bytes | SHA-256 | Architecture |
|---|---|---|---|
| `olk.exe` | 262,144 | (see evidence) | x86_64 |
| `olkmain.dll` | 4.32 MB | `3e52be8ec8fb32e36bdabb69840149235d0294c840b864a05a80716397166144` | x86_64 |
| `win32gql.dll` | 10.35 MB | `15343c024c065bde08943d4205960ab88ca485990db25220f36838331e4c0744` | x86_64 |

Evidence IDs:
- `win32gql.dll` imports: `ev_e757d6ba458448d0faa23581fa0d39653db7009ad135a2ca1d9f5919e924f95a`
- `olkmain.dll` exports: `ev_d3de1eb3391a37e716c1f44816cf8dedc378e463f82ba2f5f07e56d58b4d3580`
- `win32gql.dll` hardening: `ev_d6ee6c084f8ab3345cfcfd560e22e16a217b0add5f6566b94a64466b59d74642`

---

## Finding 1: `win32gql.dll` is NOT the network client

This is the most important finding and it contradicts the obvious guess from the filename.

The DLL is named "win32gql" (Win32 + GraphQL) and sits next to `cpprest_2_10.dll`
(Microsoft's C++ REST SDK). The natural assumption is that this file does the GraphQL
over HTTP. **The import table says otherwise.**

Complete import surface — 10 DLLs, 169 functions:

| DLL | Functions |
|---|---|
| `kernel32.dll` | 125 |
| `user32.dll` | 14 |
| `ole32.dll` | 7 |
| `oleaut32.dll` | 7 |
| `advapi32.dll` | 5 |
| `ntdll.dll` | 5 |
| `api-ms-win-core-synch-l1-2-0.dll` | 3 |
| `bcryptprimitives.dll` | 1 |
| `api-ms-win-core-winrt-error-l1-1-0.dll` | 1 |
| `shell32.dll` | 1 |
| `msi.dll` | 1 |

**Zero imports from:** `winhttp.dll`, `wininet.dll`, `ws2_32.dll`, `websocket.dll`,
`urlmon.dll`, `bcrypt.dll`/`crypt32.dll`, `winsqlite3.dll`, and no
`RoActivateInstance`/`RoGetActivationFactory` (WinRT activation).

Function-level scan for `Internet|Http|WinHttp|WebSocket|Socket|RoActivate|Crypt|Sqlite`
returned exactly **one** hit: `kernel32.dll!CreateProcessW`.

### What this means

`win32gql.dll` is a **host/plumbing layer, not a transport layer**. Its imports are what
you would expect from a library that:
- manages heap and critical sections (`HeapAlloc`, `InitializeCriticalSectionEx`, `SRW` via synch)
- does file I/O and directory enumeration (`CreateFileW`, `FindFirstFileExW`, `MoveFileExW`)
- spawns and manages **child processes** (`CreateProcessW`, `DuplicateHandle`, `CreateThread`)
- handles string/locale conversion (`MultiByteToWideChar`, `CompareStringEx`, `LCMapStringW`)

The `CreateProcessW` + `DuplicateHandle` + `CreateThread` cluster is the signature of a
**process supervisor**. The GraphQL/network work is delegated to a child process rather than
done in-process. That child is almost certainly the WebView/web-shell host, which is where
the actual HTTP stack lives (inside Chromium/Edge WebView2, not in this DLL).

**Design conclusion:** new Outlook is a process-supervisor shell over a webview. The native
DLLs orchestrate; the webview communicates. Any interop layer must target the
webview's protocol surface (CDP/DevTools or the local transport the supervisor uses), not
the native import table.

---

## Finding 2: Hardening profile is standard MSVC + CFG

From `inspect-binary-hardening` on `win32gql.dll`:

| Property | State | Basis |
|---|---|---|
| `dynamic_base` (ASLR) | enabled | DllCharacteristics 0x40 |
| `high_entropy_va` | enabled | DllCharacteristics 0x20 |
| `nx_compat` (DEP) | enabled | DllCharacteristics 0x100 |
| `guard_cf` (Control Flow Guard) | enabled | DllCharacteristics 0x4000 |
| `cfg_instrumented` | enabled | GuardFlags IMAGE_GUARD_CF_INSTRUMENTED |
| `force_integrity` | **disabled** | DllCharacteristics 0x80 clear |
| `no_seh` | disabled | DllCharacteristics 0x400 clear |
| `authenticode_present` | enabled | Security directory non-zero |
| `debug_record_present` | enabled | Debug directory non-zero |

**Caveat REA states explicitly, and I am preserving it:** `authenticode_present` records
*table presence, not signature validity*. `cfg_instrumented` is a *linker claim, not proof
CFG checks run*. Neither was verified beyond the header.

Note `force_integrity` disabled — that is normal for a DLL loaded into a signed host process
rather than a service.

---

## Finding 3: `CreateProcessW` is the interop pivot

Since the network stack is out-of-process, the boundary between native and web is a child
process. The honest, lawful interop question becomes:

> What does the supervisor launch, with what arguments, and what transport does the child
> expose for local control?

That is answerable with `inspect-native-load-image`, `decompile` on the `CreateProcessW`
call sites via Ghidra, and string search for command-line templates. It is **not**
answerable by reimplementing Microsoft's client.

---

## What we do NOT claim

- We did not verify the Authenticode signature.
- We did not execute the binary or observe runtime behavior.
- We did not decompile `olkmain.dll` or recover function bodies.
- We did not establish which child process is launched (that requires the next probe).
- We make no claim about protocol details, endpoints, or authentication.

Each of these is a named next probe, not a gap being papered over.

## Next probes (in order)

1. `inspect-native-load-image` on `olk.exe` — dependency resolution order.
2. `search` for command-line/URI templates in `olkmain.dll`.
3. `decompile` the `CreateProcessW` call site in `win32gql.dll` via Ghidra.
4. `inspect-pe-resources` on `olk.exe` — manifest, appx identity, capability declarations.
5. Compare against `WebView2Loader.dll` import surface if present in the package.

---

*Source: REA 6.9.0, Ghidra 12.2, on-host analysis of an installed program.
No Microsoft code, assets, or proprietary content is reproduced or redistributed.*
