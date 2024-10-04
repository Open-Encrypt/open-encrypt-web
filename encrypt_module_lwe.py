from module_lwe import parameters, add_vec, mul_mat_vec_simple, transpose, mul_vec_simple
from ring_lwe import sub_poly, polyadd
import numpy as np
import random
from sys import argv

np.random.seed(0xdeadbeef)

n, q, f, k = parameters()

def encrypt(A, t, m_b, f, q, r, e_1, e_2):
    """Encrypt a binary message m_b
    Args:
        A, t: public-key.
        m_b: binary message.
        q: modulus.
        f: polynomial modulus.
        e_1: integer to be encrypted.
    Returns:
        Tuple representing a ciphertext.      
    """

    half_q = int(q / 2 + 0.5)
    m = list(map(lambda x: x * half_q, m_b))

    u = add_vec(mul_mat_vec_simple(transpose(A), r, f, q), e_1, q)
    v = sub_poly(polyadd(mul_vec_simple(t, r, f, q), e_2, q, f), m, q, f)

    return u, v

r = (np.random.random([k, n]) * 3).astype(int) - 1
e_1 = (np.random.random([k, n]) * 3).astype(int) - 1
e_2 = (np.random.random([n]) * 3).astype(int) - 1

if(len(argv) > 2):
    #get public ket from argv[1] ...
    A = ...
    t = ...
    #get message from argv[2] ...
    m_b = ...
    #encrypt message using public key
    u, v = encrypt(A, t, m_b, f, q, r, e_1, e_2)