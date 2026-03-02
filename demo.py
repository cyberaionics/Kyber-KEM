#!/usr/bin/env python3
"""
CRYSTALS-Kyber (ML-KEM) — Interactive Demo.

Demonstrates key generation, encapsulation, and decapsulation
across all three security levels with timing information.
"""

import time
import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kyber.params import KYBER_512, KYBER_768, KYBER_1024, KyberParams
from kyber.mlkem import KeyGen, Encaps, Decaps


# ── Formatting helpers ────────────────────────────────────────────────────────

BOLD = "\033[1m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
DIM = "\033[2m"


def header():
    print(f"""
{CYAN}{'═' * 68}
  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗
  ██║ ██╔╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  █████╔╝  ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██╔═██╗   ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ██║  ██╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
       {BOLD}CRYSTALS-Kyber / ML-KEM from Scratch{RESET}{CYAN}
{'═' * 68}{RESET}
""")


def run_demo(params: KyberParams):
    """Run a full KEM roundtrip with the given parameter set."""
    name = params.name
    print(f"\n{BOLD}{YELLOW}┌── {name} {'─' * (50 - len(name))}┐{RESET}")
    print(f"  {DIM}Parameters: k={params.k}, η₁={params.eta1}, "
          f"η₂={params.eta2}, dᵤ={params.du}, dᵥ={params.dv}{RESET}")

    # Key Generation
    print(f"\n  {CYAN}▶ Key Generation...{RESET}", end=" ", flush=True)
    t0 = time.perf_counter()
    ek, dk = KeyGen(params)
    t_keygen = time.perf_counter() - t0
    print(f"{GREEN}✓{RESET}  {DIM}({t_keygen:.3f}s){RESET}")
    print(f"    Public key (ek)  : {len(ek):>5} bytes")
    print(f"    Private key (dk) : {len(dk):>5} bytes")

    # Encapsulation
    print(f"\n  {CYAN}▶ Encapsulation...{RESET}", end=" ", flush=True)
    t0 = time.perf_counter()
    K_enc, ciphertext = Encaps(ek, params)
    t_encaps = time.perf_counter() - t0
    print(f"{GREEN}✓{RESET}  {DIM}({t_encaps:.3f}s){RESET}")
    print(f"    Ciphertext       : {len(ciphertext):>5} bytes")
    print(f"    Shared secret    : {K_enc.hex()}")

    # Decapsulation
    print(f"\n  {CYAN}▶ Decapsulation...{RESET}", end=" ", flush=True)
    t0 = time.perf_counter()
    K_dec = Decaps(dk, ciphertext, params)
    t_decaps = time.perf_counter() - t0
    print(f"{GREEN}✓{RESET}  {DIM}({t_decaps:.3f}s){RESET}")
    print(f"    Recovered secret : {K_dec.hex()}")

    # Verify
    match = K_enc == K_dec
    if match:
        print(f"\n  {GREEN}{BOLD}✅ Keys MATCH — Secure key exchange succeeded!{RESET}")
    else:
        print(f"\n  {RED}{BOLD}❌ Keys DO NOT MATCH — Something went wrong!{RESET}")

    print(f"\n{YELLOW}└{'─' * 56}┘{RESET}")
    return match


def main():
    header()

    print(f"{BOLD}Running full ML-KEM key exchange for all security levels...{RESET}")

    all_passed = True
    for params in [KYBER_512, KYBER_768, KYBER_1024]:
        if not run_demo(params):
            all_passed = False

    print(f"\n{'═' * 68}")
    if all_passed:
        print(f"{GREEN}{BOLD}  All security levels passed! 🎉{RESET}")
    else:
        print(f"{RED}{BOLD}  Some tests failed!{RESET}")
    print(f"{'═' * 68}\n")


if __name__ == "__main__":
    main()
