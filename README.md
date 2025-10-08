# open-encrypt

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

Full-stack encrypted messaging application using lattice-based methods in Rust + PHP + SQL.

## iOS

iOS app is in development: [https://github.com/jacksonwalters/open-encrypt-ios](https://github.com/jacksonwalters/open-encrypt-ios)

## Disclaimer

This app is currently functional, but only meant for educational use, or as a demo.

The encryption methods used are post-quantum, but have not been hardened against timing attacks or other side-channel attacks. This code has not been audited for security.

---

## Encryption methods (Rust)

Rust binaries are executed directly using `shell_exec`. Uses both command line arguments and files as input.

Currently using Rust crates `ring-lwe` v0.1.8 and `module-lwe` v0.1.5. 

- https://crates.io/crates/ring-lwe
- https://crates.io/crates/module-lwe

## Database (SQL)

- Three tables are required to store `login_info`, `messages`, and `public_keys`.
- Passwords are hashed using standard hashing. 
- Secure, random tokens stored for user sessions.
- Messages are stored encrypted on the server in a SQL database.
- For both ring-LWE and module-LWE, messages are stored as compressed and encoded base64 strings.

## Backend (PHP)

Used to handle basic account creation, login, and SQL insertions/lookups. 

## Resources

- ring-LWE in Python: https://blog.openmined.org/build-an-homomorphic-encryption-scheme-from-scratch-with-python/
- ring-LWE math: https://math.colorado.edu/~kstange/teaching-resources/crypto/RingLWE-notes.pdf
- module-LWE in Python: https://cryptographycaffe.sandboxaq.com/posts/kyber-01/
- Red Hat Post-Quantum/Lattices: https://www.redhat.com/en/blog/post-quantum-cryptography-lattice-based-cryptography
- NIST Post-Quantum: https://csrc.nist.gov/projects/post-quantum-cryptography
- Latticed-based cryptography: https://thelatticeclub.com
