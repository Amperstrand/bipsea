#!/usr/bin/env python3
"""
CLI Test Vectors for BIP‑85

This test file uses the command-line version of bipsea (“bipsea derive”) to derive secrets 
according to BIP‑85. For each application, the test file shows:

  A. How the derivation path is constructed from the BIP‑85 specification.
  B. How to call bipsea via the CLI with the proper flags.
  C. That the output matches the expected test vector from the official BIP‑85.

For example, for the mnemonic application (BIP‑39) a 12‑word English mnemonic is derived 
using the path:
    m/83696968'/39'/0'/12'/0'
This tells bipsea:
  - Use purpose code 83696968' (for BIP‑85),
  - Use application code 39' (for mnemonic),
  - Use language code 0' (for English),
  - Use 12' (to indicate 128 bits of entropy for 12 words),
  - And the child index is 0'.
  
Other applications (WIF, XPRV, HEX, Base64, Base85, Dice) use similar fixed paths.

Note: This test file calls the CLI tool (using subprocess) rather than internal functions.
"""

import subprocess
import sys
import pytest

# Set the master XPRV (from the BIP‑85 test vector)
MASTER_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

def run_bipsea_derive(application: str, number: int = None, index: int = 0, special: int = None, to_lang: str = None) -> str:
    """
    Run the bipsea CLI tool to derive a secret according to BIP‑85.
    
    Parameters:
      - application: One of the allowed applications: base64, base85, dice, drng, hex, mnemonic, wif, xprv.
      - number: Length parameter (in bytes, characters, or words, depending on the application).
      - index: Child index.
      - special: For dice, number of sides.
      - to_lang: For mnemonic application, the output language (e.g. "eng" for English).
    
    The master XPRV is passed with -x.
    
    The CLI “derive” command is called with these options and the output (as text) is returned.
    """
    cmd = ["bipsea", "derive", "-a", application, "-x", MASTER_XPRV, "-i", str(index)]
    if number is not None:
        cmd.extend(["-n", str(number)])
    if special is not None:
        cmd.extend(["-s", str(special)])
    if to_lang is not None:
        cmd.extend(["-t", to_lang])
    try:
        result = subprocess.check_output(cmd, encoding="utf-8").strip()
        return result
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Command {' '.join(cmd)} failed: {e}")

# -----------------------------------------------------------------------------
# CLI Test Vectors from BIP‑85
#
# The following tests use the bipsea CLI to derive the test vectors as specified in BIP‑85.
# -----------------------------------------------------------------------------

def test_cli_mnemonic_12():
    # For a 12-word mnemonic, the derivation path is:
    #    m/83696968'/39'/0'/12'/0'
    # Expected mnemonic (as per BIP‑85 test vector):
    expected = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    output = run_bipsea_derive("mnemonic", number=12, index=0, to_lang="eng")
    assert output == expected, f"Mnemonic 12 CLI: Expected {expected}, got {output}"

def test_cli_mnemonic_18():
    # Derivation path: m/83696968'/39'/0'/18'/0'
    expected = ("near account window bike charge season chef number sketch tomorrow excuse sniff circle "
                "vital hockey outdoor supply token")
    output = run_bipsea_derive("mnemonic", number=18, index=0, to_lang="eng")
    assert output == expected, f"Mnemonic 18 CLI: Expected {expected}, got {output}"

def test_cli_mnemonic_24():
    # Derivation path: m/83696968'/39'/0'/24'/0'
    expected = ("puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin "
                "tonight reason outdoor destroy simple truth cigar social volcano")
    output = run_bipsea_derive("mnemonic", number=24, index=0, to_lang="eng")
    assert output == expected, f"Mnemonic 24 CLI: Expected {expected}, got {output}"

def test_cli_wif():
    # For HD-Seed WIF, the derivation path is:
    #    m/83696968'/2'/0'
    expected = "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
    output = run_bipsea_derive("wif", index=0)
    assert output == expected, f"WIF CLI: Expected {expected}, got {output}"

def test_cli_xprv():
    # For XPRV, the derivation path is:
    #    m/83696968'/32'/0'
    expected = "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
    output = run_bipsea_derive("xprv", index=0)
    assert output == expected, f"XPRV CLI: Expected {expected}, got {output}"

def test_cli_hex():
    # For HEX, the derivation path is:
    #    m/83696968'/128169'/64'/0'
    expected = ("492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c")
    output = run_bipsea_derive("hex", number=64, index=0)
    assert output == expected, f"HEX CLI: Expected {expected}, got {output}"

def test_cli_pwd_base64():
    # For Base64 password, derivation path is:
    #    m/83696968'/707764'/21'/0'
    expected = "dKLoepugzdVJvdL56ogNV"
    output = run_bipsea_derive("base64", number=21, index=0)
    assert output == expected, f"Password Base64 CLI: Expected {expected}, got {output}"

def test_cli_pwd_base85():
    # For Base85 password, derivation path is:
    #    m/83696968'/707785'/12'/0'
    expected = "_s`{TW89)i4`"  # Note: the expected value includes backticks exactly.
    output = run_bipsea_derive("base85", number=12, index=0)
    assert output == expected, f"Password Base85 CLI: Expected {expected}, got {output}"

def test_cli_dice():
    # For Dice, the derivation path is:
    #    m/83696968'/89101'/6'/10'/0'
    # This means: use a dice with 6 sides, produce 10 rolls, and use child index 0.
    expected = "1,0,0,2,0,1,5,5,2,4"
    output = run_bipsea_derive("dice", number=10, index=0, special=6)
    assert output == expected, f"Dice CLI: Expected {expected}, got {output}"

if __name__ == "__main__":
    pytest.main()
