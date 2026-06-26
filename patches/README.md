# Patches

This directory contains **build-time patches** applied to the sing-box core source code
before compilation. Patches are applied on the fly by the CI workflow — no fork needed.

## Directory Layout

```
patches/
  README.md
  common/           # Applied to ALL targets (Stable + Testing)
    *.patch
  reF1nd_Stable/    # Applied ONLY to reF1nd_Stable builds
    *.patch
  reF1nd_Testing/   # Applied ONLY to reF1nd_Testing builds
    *.patch
```

## How to Add a Patch

1. Make your change inside a lokal checkout of
   [`reF1nd/sing-box`](https://github.com/reF1nd/sing-box).
2. Generate the patch:
   ```bash
   git diff > my-change.patch
   # or for a single commit:
   git format-patch -1 HEAD
   ```
3. Place the `.patch` file in the appropriate subdirectory above.
4. Commit and push. The workflow applies it automatically.

## Patch Requirements

- **Path-relative to sing-box root.** A diff hunk referencing
  `a/cmd/sing-box/main.go` is applied to
  `sing-box/cmd/sing-box/main.go` inside the CI checkout.
- **Must apply cleanly.** Patch failure is a hard build error.
  If upstream code changes break the patch, update or remove it.
- **Plain `git diff` format.** Context lines, hunks, standard unified diff.

## Verification

After adding a patch, trigger a `workflow_dispatch` build and verify
the "Apply Patches" step in the log:

```
::notice::Applying patch my-change.patch
Applied 1 patch(es).
```

If a patch fails, the build stops immediately with an error showing
which file/hunk conflicted.
