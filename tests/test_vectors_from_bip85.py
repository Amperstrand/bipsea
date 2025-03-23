#!/usr/bin/env python3
"""
Test Vectors for BIP‑85 using bipsea’s internal API.

IMPORTANT NOTES:
---------------
1. The raw entropy test vectors (Test Vectors 1 and 2) are computed by deriving an arbitrary subpath 
   (e.g. m/83696968'/0'/0' and m/83696968'/0'/1'). We extract the 32-byte private key (ignoring the 
   leading 0x00) and compute HMAC‑SHA512 with key "bip-entropy-from-k". These outputs are the raw entropy.
2. Test Vector 3 (DRNG) uses the raw entropy from Test Vector 1 as a seed for a DRNG (SHAKE256) to 
   produce 80 bytes of deterministic random output.
3. The application test vectors (BIP39 mnemonics, HD‑Seed WIF, XPRV, HEX, Base64, Base85, and Dice) are derived 
   according to the BIP‑85 rules (using fixed derivation path formats).
4. Because bipsea does not expose a convenience function to derive an arbitrary subpath, we define our own helper,
   `derive_sub_xprv`, to support the raw entropy tests.
"""

import hmac
import hashlib
import pytest

# Import necessary functions from bipsea's internal modules.
from bipsea.bip32types import parse_ext_key
from bipsea.bip32 import derive_key, hmac_sha512
from bipsea.bip85 import (
    derive,
    DRNG,
    to_entropy,
    to_hex_string,
    HMAC_KEY,
    APPLICATIONS,
    PURPOSE_CODES,
    apply_85,
)
from bipsea.bip39 import N_WORDS_META  # For mnemonic meta info

MASTER_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)

# ---------------------------------------------------------------------------
# Helper Function: derive_sub_xprv
#
# Bipsea does not expose a convenience function to derive an arbitrary subkey (e.g. m/83696968'/0'/0').
# We need this helper to derive the raw extended key so that we can compute the HMAC‑SHA512 of its 32-byte
# private key (ignoring the leading 0x00) to obtain the raw entropy.
# ---------------------------------------------------------------------------
def derive_sub_xprv(master_xprv: str, path: list) -> (str, str):
    """
    Derive a sub-xprv from the master_xprv using a list of integers (each representing a hardened index).

    For example, for the path m/83696968'/0'/0', pass path = [83696968, 0, 0].

    Returns:
      (sub_xprv_str, private_key_hex)
      where sub_xprv_str is the base58-encoded representation of the derived extended key,
      and private_key_hex is the 32-byte private key (excluding the leading 0x00) in hex.
    """
    master = parse_ext_key(master_xprv)
    path_strs = ["m"] + [f"{p}'" for p in path]
    print(f"Debug: Full derivation path: {path_strs}")
    sub = derive_key(master, path_strs, private=True)
    privkey_hex = sub.data[1:].hex()  # skip the leading 0x00
    return str(sub), privkey_hex

# ---------------------------------------------------------------------------
# Raw Entropy and DRNG Tests
#
# Test Vectors 1 & 2: Compute raw entropy as HMAC‑SHA512(HMAC_KEY, private_key) for two subpaths.
#
# Test Vector 3: Use the raw entropy from Test Vector 1 as a seed for DRNG (SHAKE256) to produce 80 bytes.
# ---------------------------------------------------------------------------
def test_raw_entropy_1():
    expected = (
        "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
    )
    # Derive subkey at m/83696968'/0'/0'
    _, privkey_hex = derive_sub_xprv(MASTER_XPRV, [83696968, 0, 0])
    computed = hmac_sha512(HMAC_KEY, bytes.fromhex(privkey_hex)).hex()
    print(f"Debug (Raw Entropy 1): private key = {privkey_hex}")
    assert computed == expected, f"Raw Entropy Test 1: Expected {expected}, got {computed}"

def test_raw_entropy_2():
    expected = (
        "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
    )
    # Derive subkey at m/83696968'/0'/1'
    _, privkey_hex = derive_sub_xprv(MASTER_XPRV, [83696968, 0, 1])
    computed = hmac_sha512(HMAC_KEY, bytes.fromhex(privkey_hex)).hex()
    assert computed == expected, f"Raw Entropy Test 2: Expected {expected}, got {computed}"

def test_drng():
    # Use raw entropy from Test Vector 1 as seed for DRNG.
    _, privkey_hex = derive_sub_xprv(MASTER_XPRV, [83696968, 0, 0])
    seed = hmac_sha512(HMAC_KEY, bytes.fromhex(privkey_hex)).hex()
    expected = (
        "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd883d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc8c7355b87a925a37ee405a7502991111"
    )
    seed_bytes = bytes.fromhex(seed)
    drng_instance = DRNG(seed_bytes)
    computed = to_hex_string(drng_instance.read(80))
    assert computed == expected, f"DRNG Test: Expected {expected}, got {computed}"

# ---------------------------------------------------------------------------
# Application Test Vectors
#
# These tests use the fixed derivation paths defined in the BIP‑85 specification.
# For each application, we manually build the full derivation path and then use derive() and apply_85().
# ---------------------------------------------------------------------------
def test_mnemonic_12():
    expected = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    # Derivation path for 12-word English mnemonic: m/83696968'/39'/0'/12'/0'
    path = "m/83696968'/39'/0'/12'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"Mnemonic 12: Expected {expected}, got {result}"

def test_mnemonic_18():
    expected = ("near account window bike charge season chef number sketch tomorrow excuse sniff circle "
                "vital hockey outdoor supply token")
    path = "m/83696968'/39'/0'/18'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"Mnemonic 18: Expected {expected}, got {result}"

def test_mnemonic_24():
    expected = ("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin "
                "tonight reason outdoor destroy simple truth cigar social volcano")
    path = "m/83696968'/39'/0'/24'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"Mnemonic 24: Expected {expected}, got {result}"

def test_wif():
    expected = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
    path = "m/83696968'/2'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"WIF: Expected {expected}, got {result}"

def test_xprv():
    expected = "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
    path = "m/83696968'/32'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"XPRV: Expected {expected}, got {result}"

def test_hex():
    expected = ("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c")
    path = "m/83696968'/128169'/64'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"HEX: Expected {expected}, got {result}"

def test_pwd_base64():
    expected = "dKLoepugzdVJvdL56ogNV"
    path = "m/83696968'/707764'/21'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"Password Base64: Expected {expected}, got {result}"

def test_pwd_base85():
    expected = "_s`{TW89)i4`"
    path = "m/83696968'/707785'/12'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"Password Base85: Expected {expected}, got {result}"

def test_dice():
    expected = "1,0,0,2,0,1,5,5,2,4"
    path = "m/83696968'/89101'/6'/10'/0'"
    master = parse_ext_key(MASTER_XPRV)
    derived = derive(master, path)
    result = apply_85(derived, path)["application"]
    assert result == expected, f"Dice: Expected {expected}, got {result}"

if __name__ == "__main__":
    pytest.main()
