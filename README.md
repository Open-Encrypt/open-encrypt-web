# open-encrypt
Full-stack encrypted messaging application using lattice-based methods in Python + PHP + SQL.

**NOTE**: This is a demo for educational purposes only. It is not meant for real-world use.

**ENCRYPTION METHODS**: ring-LWE, module-LWE

**RESOURCES**:

- ring-LWE in Python: https://blog.openmined.org/build-an-homomorphic-encryption-scheme-from-scratch-with-python/
- module-LWE in Python: https://cryptographycaffe.sandboxaq.com/posts/kyber-01/
- ring-LWE notes: https://math.colorado.edu/~kstange/teaching-resources/crypto/RingLWE-notes.pdf
- NIST Post-Quantum: https://csrc.nist.gov/projects/post-quantum-cryptography
- Red Hat Post-Quantum/Lattices: https://www.redhat.com/en/blog/post-quantum-cryptography-lattice-based-cryptography
- Latticed-based cryptography: https://thelatticeclub.com

---

**SQL**: 

- Three tables are required to store login_info, messages, and public_keys.
- Passwords are hashed using standard hashing. 
- Secure, random tokens stored for user sessions.
- Messages are stored encrypted. The inflation ratio is ~13.7 for ring-LWE.
- For ring-LWE, public keys are a `string` representing two (cyclotomic, modular) polynomials as `int` arrays.
- For module-LWE, public keys are a `string` representing a random matrix `A` and vector `t` with (cyclotomic, modular) polynomial coefficients.

**PHP**:

Used to handle basic account creation, login, and SQL insertions/lookups. 

**Python**:

Python scripts are executed directly using `shell_exec`. Output is printed and passed back as a string.
  
