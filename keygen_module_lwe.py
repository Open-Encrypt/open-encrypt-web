import numpy as np
import random
import json
from module_lwe import parameters, add_vec, mul_mat_vec_simple

np.random.seed(0xdeadbeef)

def keygen(k, q, poly_mod):
    """Generate a public and secret keys
    Args:
        size: size of the polynoms for the public and secret keys.
        modulus: coefficient modulus.
        poly_mod: polynomial modulus.
    Returns:
        Public and secret key.
    """

    degree_poly_mod = len(poly_mod) #degree of the polynomial modulus

    A = (np.random.random([k, k, degree_poly_mod]) * q).astype(int) #note A \in R^{k x k}, each entry is a deg(f) list
    s = (np.random.random([k, degree_poly_mod]) * 3).astype(int) - 1 #each coefficient is in {-1,0,+1}
    e = (np.random.random([k, degree_poly_mod]) * 3).astype(int) - 1 #each coefficient is in {-1,0,+1}
    t = add_vec(mul_mat_vec_simple(A, s, f, q), e, q) #form the vector A*s + e

    return (A,t), s

n, q, poly_mod, k = parameters()

pk, sk = keygen(k,q,poly_mod)

keys = {"secret":sk.tolist(), "public_A":pk[0].tolist(), "public_t":[a.tolist() for a in pk[1]]}
print(json.dumps(keys))