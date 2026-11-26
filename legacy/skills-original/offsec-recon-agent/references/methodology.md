
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Recon Methodology Reference

Technical command reference for the Recon Sub-Agent. The orchestration rules and pipeline order are defined in `../SKILL.md`; this file holds the exact commands, flags, and supporting techniques.

## Pipeline Commands

### [1] Pass 1 -- Subdomain enumeration

```bash
subfinder -d target.com -o pass1.txt
```

### [2] Scope filter #1

Filter `pass1.txt` against `scope.allowed` / `scope.forbidden` (exact hosts, suffixes, and any regex rules from the engagement scope) and write the survivors to `pass1_scoped.txt`. Rejected entries -> `out_of_scope`, never carried forward. This scoped file -- not the raw `pass1.txt` -- is the input for Pass 2.

### [3] Pass 2 -- Manual two-pass recursion

```bash
subfinder -dL pass1_scoped.txt -o pass2.txt
```

This is deliberate **manual recursion**: the scoped Pass-1 hosts are fed back as seeds for a second pass. Pass 2 is opportunistic -- most passive sources return little below the apex, so low yield here is normal, not an error; the gate that matters is step 5.

Run Pass 2 only when the scoped Pass-1 yield is large enough to make sub-subdomain recursion plausible (>= ~50 hosts). Below that, the extra API calls almost never buy anything; skip the pass, leave `pass2.txt` empty, and step 4 still works. Do **not** use subfinder's built-in `-recursive` flag -- the two-pass form keeps the intermediate scope gate (step 2) in the loop and produces cleaner provenance.

### [4] Merge + dedup

```bash
cat pass1_scoped.txt pass2.txt | sort -u > subdomains_final.txt
```

### [5] Scope filter #2

Final gate on `subdomains_final.txt`. No domain reaches httpx without passing both filters.

### [6] Probing + fingerprinting -- the ONLY httpx call

```bash
httpx -l subdomains_final.txt \
  -tech-detect -title -status-code -content-type \
  -json -o alive.json
```

One pass, one JSON artifact. `-tech-detect`, `-title`, `-status-code`, and `-content-type` together produce the fingerprint record for every live host. Everything downstream -- scoring, ranking, asset inventory, handoff notes -- reads from `alive.json`. **Never run a second httpx pass.**

### [7a] + [7b] + [7c] -- Parallel tracks (all from alive.json)

```bash
# 7a -- active crawling (write the seed list to a real file; no process substitution)
jq -r '.url' alive.json > urls.txt
katana -list urls.txt -depth 3 -c 10 -o crawl/katana.txt

# 7b -- archive URLs
jq -r '.host' alive.json | waybackurls > crawl/wayback.txt

# 7c -- scoring & ranking on alive.json itself (see Scoring below)
```

### [8] Merge crawl results + uro

```bash
cat crawl/katana.txt crawl/wayback.txt | uro > urls_merged.txt
```

`uro` normalizes and dedupes parameterized URLs (collapses `?id=1`, `?id=2`, ... into one representative).

### [9] gf classification -- per vulnerability family

The list is closed -- exactly 8 patterns, one per downstream vulnerability-family agent:

```bash
gf sqli     < urls_merged.txt > classified/sqli_urls.txt      # 1 SQL injection
gf xss      < urls_merged.txt > classified/xss_urls.txt       # 2 XSS
gf ssrf     < urls_merged.txt > classified/ssrf_urls.txt      # 3 SSRF
gf lfi      < urls_merged.txt > classified/lfi_urls.txt       # 4 LFI / path traversal
gf idor     < urls_merged.txt > classified/idor_urls.txt      # 5 IDOR
gf redirect < urls_merged.txt > classified/redirect_urls.txt  # 6 open redirect
gf ssti     < urls_merged.txt > classified/ssti_urls.txt      # 7 SSTI
gf rce      < urls_merged.txt > classified/rce_urls.txt       # 8 RCE / command injection
```

Decision notes:

- The **8th family is RCE / command injection** (standard `gf rce` pattern: `cmd=`, `exec=`, `ping=`, `query=`, `do=`, ...). Open redirect stays folded into `redirect`; it is not a separate family.
- **File-upload** has no standard gf pattern -- upload endpoints are caught by the prioritization heuristics and reported via `interesting_findings` / `delegation_requests` instead of a classified file.

One classified file per downstream agent family. These map 1:1 onto `urls.by_vuln_family` in the output JSON (with `other_urls` as the catch-all remainder, not a family).

### [10] Signal + report

Write the signal file (`{"status": "done", "task_id": "...", "artifacts": {...}}`) for the orchestrator's filesystem watcher, then the final comprehensive report, then return the structured JSON to the Main Agent.

## Scoring & Ranking (step 7c detail)

Additive points per domain. The ranking exists to tell the Main Agent **where the attack surface is densest** -- it is a prioritization and handoff artifact, not a target list for any tool run by this agent.

| Signal | Points |
|---|---|
| Status 200 | +3 |
| Status 403 | +2 (interesting -- protected but exists) |
| Tech: API | +3 |
| Tech: Admin / internal panel | +3 |
| Tech: known DevOps tool | +2 |
| `dev`, `staging`, `test`, `internal`, `beta` in subdomain name | +1 per keyword |
| URLs attributed to this domain from katana + waybackurls | count / 10 |

Scoring runs in two phases: compute the base score (status / tech / keywords) from `alive.json` during track 7c, then -- once 7a/7b have finished -- add the URL-count signal (count / 10) and emit the final `ranked_targets`. 7a and 7b run in parallel with each other and with the base scoring in 7c; the final `ranked_targets` is produced only after the per-domain URL counts exist, not as a parallel track.

Counting source (important): count each domain's URLs from the **raw** crawl outputs (`crawl/katana.txt` + `crawl/wayback.txt`, attributed by host), before `uro`. Do not count from `urls_merged.txt` -- `uro` collapses parameterized variants (`?id=1`, `?id=2`, ... into one representative) and would undercount dense domains. Exact-duplicate lines may be dropped with `sort -u`, but distinct parameter values must each count.

`ranked_targets` is used to seed `interesting_findings` and `delegation_requests`; nothing on it is fuzzed, brute-forced, or fed to any enumeration tool.

## Supplementary Enumeration Techniques

Beyond subfinder's sources, when Pass 1 yield is thin:

- **crt.sh**: `curl -s "https://crt.sh/?q=%25.target.com&output=json"` -- parse cert transparency logs for names.
- Passive DNS / cert transparency cross-referencing, GitHub/GitLab dorking, cloud bucket permutations.
- Feed anything new through the scope filter before merging into `subdomains_final.txt`.

## API Spec & GraphQL Discovery

Runs alongside step 9; results populate `openapi_specs[]` and `graphql_endpoints[]` in the output. This is **discovery only** -- never introspection-test or fuzz a schema here; that belongs to `offsec-api-agent`.

- **OpenAPI / Swagger**: from `urls_merged.txt`, match `openapi`, `swagger`, `api-docs`, `/v3/api-docs`, `redoc`, `postman` and any `.json`/`.yaml` under an `/api` path. Record each reachable spec URL in `openapi_specs[]` (with `url` and, when visible, `version`). Do not parse deeply beyond confirming it is a spec.
- **GraphQL**: match `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql` in crawl/archive output. Record each in `graphql_endpoints[]` and raise a `delegation_request` to `offsec-api-agent` (class `graphql.introspection`). A 200 on GET is enough to record; do not run introspection.

## Cloud Asset Discovery

Runs alongside steps 1-8; results populate `cloud_assets[]`. Discovery only -- never claim a bucket, and never touch a non-authorized tenant.

- **Bucket permutations**: derive candidate S3/GCS/Azure Blob names from in-scope hostnames, brand tokens, and `dev/staging/test` variants; record any that resolve/answer in `cloud_assets[]` as `{type: "s3|gcs|azure", url: "...", exposed: true|false|unknown}`.
- **CNAME chase**: note CNAME targets from `alive.json`/DNS output that point at cloud providers (S3 website, Azure `*.cloudapp.azure.com`, Netlify, Vercel, Heroku, GitHub Pages) -- record as `{type: "cname", url: "<target>", exposed: "unknown"}` for `offsec-cloud-infra-agent` to adjudicate (dangling/claimable is that agent's call).
- `exposed` reflects only what is directly observable from the enumeration response (e.g. an anonymous listing banner); it is a hint, not a confirmed finding -- the takeover/storage verdict belongs to `offsec-cloud-infra-agent`.

## Endpoint Discovery Notes

- Crawl depth: **3 max** (katana `-depth 3`).
- Dedupe key for endpoints: `(normalized-path, param-set)`. Neither katana nor waybackurls in this pipeline records HTTP methods; a method observed in crawl output is kept as metadata, not part of the dedupe key.
- Parse JS bundles surfaced by the crawl for: `/api/` routes, hardcoded tokens, versioned endpoints.
- Endpoint discovery in this pipeline comes from katana + waybackurls only. There is no wordlist-driven path enumeration stage.

## Fingerprinting Cheatsheet

- **Headers**: `Server`, `X-Powered-By`; cookies -- `JSESSIONID` = Java, `.ASPXAUTH` = .NET, `PHPSESSID` = PHP.
- **WAF signs**: Cloudflare (`cf-ray` header), Akamai, Imperva (`incap_ses` cookie). Record any WAF in `assets[].waf` and in `blocks_detected` if it interferes.
- **GraphQL**: if a GraphQL endpoint (`/graphql`, `/graphiql`, `/api/graphql`) appears in crawl or archive output, note it in `graphql_endpoints[]` and `interesting_findings`, and raise a `delegation_request`. Do not probe it -- introspection testing belongs to the specialist agents.

## Prioritization Heuristics (attack-surface ranking context)

When scoring ties break or when writing `interesting_findings`, prefer:

1. Auth/session endpoints (login, reset, OAuth callbacks)
2. File upload / import endpoints
3. Payment / pricing / quantity flows
4. Endpoints with user-controlled parameters (search, redirect, fetch-URL)
5. Admin panels and debug interfaces

These heuristics inform ranking and handoff notes -- they never override the numeric score in `ranked_targets`.

## Block / Rate-Limit Handling

- Keep httpx and katana concurrency conservative (`httpx -rl`, `katana -c` / `-rl`); they are the only tools touching live hosts at volume. Start low and raise only if the target tolerates it.
- Any 429, connection reset, WAF challenge page, or hard ban during a run -> record in `blocks_detected` with host, tool, type, and detail; back off (or skip that host) rather than retrying aggressively.
- This applies identically to httpx and katana. Neither retries a blocked host through a different IP, different headers, or a different identity.
- If a block kills a pipeline stage entirely, finish what remains and return `status: "partial"` with the gap documented.
