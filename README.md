# Baby-Kyber: A Ring-LWE Cryptosystem from First Principles

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Cryptography](https://img.shields.io/badge/Domain-Post--Quantum_Cryptography-success)
![Status](https://img.shields.io/badge/Status-Active_Development-orange)

## Overview
This repository contains a from-scratch implementation of a Post-Quantum Cryptographic (PQC) public-key encryption scheme based on the **Ring-Learning With Errors (Ring-LWE)** hard problem. 

Designed as an educational research initiative, this project intentionally avoids high-level cryptographic libraries or optimized math modules (like NumPy) to demonstrate a fundamental understanding of polynomial ring arithmetic, stochastic noise distribution, and lattice-based cryptographic mechanics. The architecture closely mirrors the foundational logic of the NIST-standardized **CRYSTALS-Kyber** algorithm.

## Mathematical Foundation
The security of this scheme relies on the hardness of distinguishing noisy linear equations from uniform randomness over a polynomial ring.



* **The Ring:** Arithmetic is performed over the polynomial ring $\mathcal{R}_q = \mathbb{Z}_q[X] / (X^n + 1)$.
* **Parameters:** Mapped to Kyber-512 specifications:
  * Dimension ($n$): 256
  * Modulus ($q$): 3329
* **Negacyclic Property:** Polynomial multiplication relies on the wrap-around property where $X^n \equiv -1 \pmod q$.

## Project Architecture
The system is divided into modular components separating the algebraic engine from the cryptographic protocols:

* `config.py`: Global parameters ($n, q$) and system constants.
* `poly.py`: The core algebraic engine. Handles element-wise addition/subtraction and $O(n^2)$ polynomial multiplication with modulo reduction.
* `kyber.py`: *(In Progress)* Implements the Public Key Infrastructure (PKI):
  * **KeyGen:** Generation of secret vectors and calculation of noisy public matrices.
  * **Encrypt:** Message encoding mapped to high/low energy states in the polynomial.
  * **Decrypt:** Error-correction logic to strip stochastic noise and recover the plaintext bit.

## Algorithmic Complexity & Optimization
Currently, polynomial multiplication is implemented using a standard schoolbook approach with a time complexity of $O(n^2)$. 

To meet the rigorous efficiency standards required in competitive algorithmic environments, the next phase of this project will replace this with the **Number Theoretic Transform (NTT)**, reducing the multiplication time complexity to $O(n \log n)$. This is critical for defending against timing side-channel attacks in real-world deployments.

## Future Roadmap: Systems-Level Port
While Python serves as the mathematical prototype, high-performance cryptography requires strict memory control and constant-time execution. Future iterations of this project will include:
1. **Bare-Metal C Translation:** Porting the algebraic engine to pure C99, utilizing stack-only memory allocation to mimic embedded hardware constraints.
2. **Kernel-Level Integration:** Exploring the integration of this PQC logic as a Linux Kernel Module to test high-performance, low-latency cryptographic handshakes.

---
*Developed for research and exploration in Quantum Information Security.*
# Kyber-KEM
