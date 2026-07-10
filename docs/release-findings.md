# Release Findings Ledger

Append-only log of release-packaging findings for apiauth and its
downstream package-manager manifests (scoop-bucket, homebrew-tap).
Each entry has a stable `id`, a `status`, and a reproducible evidence trail.

Status legend: `open` (unresolved / needs human action) · `aligned` (fix
applied locally, pending merge/push) · `resolved` (verified in trunk).

---

## F-0001 — scoop and homebrew disagree on v0.2.0 tarball sha256

- **id:** F-0001
- **opened:** 2026-07-08
- **component:** apiauth v0.2.0 release tarball
- **status:** aligned   <!-- local manifests corrected; needs commit+push to trunk -->
- **severity:** high (broken/integrity-blocking install on one channel)

### Finding
The v0.2.0 source tarball
`https://github.com/Coding-Dev-Tools/apiauth/archive/refs/tags/v0.2.0.tar.gz`
was declared with **two different** sha256 hashes across the two package
managers, so at most one could be correct:

| manifest                                | declared sha256 (before)                          |
|-----------------------------------------|---------------------------------------------------|
| scoop-bucket `bucket/apiauth.json`      | `e9945fb0c355337d44d7a88795594e85187b0616120d5953b7b995447d13df73` |
| homebrew-tap `Formula/apiauth.rb`       | `88ab13398ff83060a6cbd96fa6f19614ec6ee24e8d9884a02ab4bbf13ad48e8e` |

The sandbox cannot download the codeload tarball (curl/wget/fetch are
intercepted — see homebrew-tap/AGENTS.md), so the hash was reproduced
locally from the git tag instead.

### Evidence (reproducible, offline)
Reproduce the exact bytes GitHub's codeload serves from the local tag:

```sh
cd apiauth
git archive --format=tar --prefix=apiauth-0.2.0/ v0.2.0 | gzip -n | sha256sum
# -> 88ab13398ff83060a6cbd96fa6f19614ec6ee24e8d9884a02ab4bbf13ad48e8e
```

- tag `v0.2.0` -> commit `f6542649d9759df58867bb8bb407e1368e8ccf3f`
- top-level dir of served tarball: `apiauth-0.2.0/` (GitHub strips the
  leading `v` from the tag for the archive directory name)
- gzip wrapper is reproducible (`gzip -n`: mtime=0, no name field), so
  the streamed hash is byte-stable across runs (verified twice).
- produced tarball size: 12632 bytes.

### Verdict
Correct sha256 = `88ab13398ff83060a6cbd96fa6f19614ec6ee24e8d9884a02ab4bbf13ad48e8e`
(homebrew-tap was right; scoop-bucket was wrong).

### Action taken (this pass)
- scoop-bucket `bucket/apiauth.json` -> hash set to `88ab1339…`.
- homebrew-tap `Formula/apiauth.rb` -> already correct, left unchanged.
- Aligned in **both** local working copies:
  - `workspace/scoop-bucket/bucket/apiauth.json`
  - `Documents/Github/scoop-bucket/bucket/apiauth.json`
  - `workspace/homebrew-tap/Formula/apiauth.rb` (unchanged, verified)
  - `Documents/Github/homebrew-tap/Formula/apiauth.rb` (unchanged, verified)
- Stale value `e9945fb0…` confirmed absent from all four manifests.

### Remains open (follow-up)
- Commit + push the corrected `apiauth.json` to scoop-bucket trunk so the
  published channel validates. Re-run `scoop checkup apiauth` after push.
- Root-cause how the stale `e9945fb0…` hash got into the scoop manifest
  (likely a hand-entered or pre-tag value); add a release checklist step
  to derive the hash via the `git archive | gzip -n` command above so the
  two channels can never drift again.