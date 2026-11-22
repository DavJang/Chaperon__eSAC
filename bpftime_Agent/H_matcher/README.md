# H_matcher — Hyperscan L7 Matcher (eSAC-authored)

The L7 pattern-matching provider that the `C_Filter` gate calls (via bpftime's **ufunc**
mechanism) to inspect application-layer content.

- **Role (DNS-aware v2).** Parse the **DNS QNAME** out of the wire format, normalize it
  (lowercase), and match the **parsed domain** against a Hyperscan pattern DB
  **case-insensitively and anchored to label boundaries** (`(^|\.)domain$` — the domain and its
  subdomains, never an arbitrary substring). This is the same detection semantics as a DNS IDS.
- **Entry symbol.** `esac_hs_scan(batch, count)` — batched, once per burst; resolved by bpftime at
  run time. Source `src/esac_hs_ufunc.c` → `esac_hs_ufunc.so` (links Hyperscan, `-lhs`).
- **Scope & limitations (documented).**
  - Case-insensitive (`HS_FLAG_CASELESS`); label-boundary match (domain + subdomain, **no**
    substring false-positive); bounds-checked QNAME parse; trailing EDNS/padding allowed; first
    question only.
  - **DNS name compression is NOT decompressed.** A QNAME with a `0xC0` compression pointer is
    treated as not-clean and the packet **falls back to a raw-payload Hyperscan scan**, which is
    **not** equivalent to proper decompression — a blocked domain split across a compression
    pointer can be missed. Non-DNS / malformed payloads also take the raw-scan fallback.
- **Pattern DB.** Built by `hsdb_ctl/{esac_hs_ctl_rx, esac_dom_ctl_bulk}` from a domain list (one
  domain per line); mapped read-only. Default patterns under `patterns/`.
- **Correctness.** Verified by an offline unit test (lowercase / UPPERCASE / mixed-case /
  subdomain-suffix / benign / substring / prefix-not-boundary) against the 17,197-pattern DB.
- **Upstream dependency.** Hyperscan (`libhyperscan-dev`); runs on the bpftime Agent runtime.
- **Build.** `gcc -shared -fPIC -O2 src/esac_hs_ufunc.c -o esac_hs_ufunc.so -lhs` (see `BUILD.md`).

> Benchmark note: the throughput headline numbers (89–96 % intra; ~7.5× a DPDK-IPS baseline at 4
> matched cores) were measured with the **previous raw-payload-scan** provider. The DNS-aware v2
> here is correctness-verified and re-measured on the inter-host payload sweep (≈ 83–101 %); the
> remaining sweeps and the IPS comparison are **pending re-measurement against v2**.
