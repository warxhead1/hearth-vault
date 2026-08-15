#!/usr/bin/env bash
# Install hearth-vault from this checkout, with the TPM2 backend enabled if
# this machine can actually build and use it.
#
# Why this script exists: `tpm2` is an opt-in Cargo feature because it links
# libtss2-esys, a C library that does not exist on macOS or Windows and is not
# installed on most Linux boxes. That makes it wrong as a DEFAULT feature -- it
# would break `cargo install hearth-vault` for nearly everyone -- but it also
# means a machine that does have a TPM has to remember to pass the flag on
# every reinstall. Detect it instead of remembering it.
#
# Runtime TPM selection is already automatic (Tpm2Backend::is_available()
# probes for a reachable TPM and falls through to the OS keyring). The only
# question here is whether the code gets compiled in at all.
set -euo pipefail

cd "$(dirname "$0")/.."

features=()
reason="no TPM2: "

# Both halves have to be true. A TPM with no headers cannot build; headers with
# no TPM build fine but seal to nothing, so there is no point paying for it.
have_device=false
have_headers=false

# tpmrm0 is the kernel resource manager. Prefer it over raw tpm0: it arbitrates
# between processes, which matters because hearth-api holds the TPM too.
for dev in /dev/tpmrm0 /dev/tpm0; do
    if [ -r "$dev" ]; then have_device=true; break; fi
done

if command -v pkg-config > /dev/null && pkg-config --exists tss2-esys; then
    have_headers=true
fi

if $have_device && $have_headers; then
    features=(--features tpm2)
    reason="TPM2 enabled"
elif $have_device; then
    reason+="found a TPM device but no tss2-esys headers (install libtss2-dev)"
elif $have_headers; then
    reason+="tss2-esys is installed but no readable /dev/tpmrm0 (are you in the 'tss' group?)"
else
    reason+="no TPM device and no tss2-esys headers"
fi

echo "==> $reason"
echo "==> cargo install --path . --locked ${features[*]-}"
cargo install --path . --locked "${features[@]}"

# Prove which backends the installed binary actually has, rather than trusting
# that the flags above did what they look like they did.
echo
"$(command -v hearth-vault)" --version
"$(command -v hearth-vault)" status 2>/dev/null || true
