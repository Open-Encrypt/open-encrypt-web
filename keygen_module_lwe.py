import numpy as np
import random
import json
from module_lwe import parameters, add_vec, mul_mat_vec_simple

np.random.seed(0xdeadbeef)

n, q, f, k = parameters()

def keygen(k, q, f):
    """Generate a public and secret keys
    Args:
        n: degree of polynomial modulus
        q: coefficient modulus.
        f: polynomial modulus.
        k: rank of modules.
    Returns:
        Public and secret key.
    """

    A = (np.random.random([k, k, n]) * q).astype(int) #note A \in R^{k x k}, each entry is a deg(f) list
    s = (np.random.random([k, n]) * 3).astype(int) - 1 #each coefficient is in {-1,0,+1}
    e = (np.random.random([k, n]) * 3).astype(int) - 1 #each coefficient is in {-1,0,+1}
    t = add_vec(mul_mat_vec_simple(A, s, f, q), e, q, f) #form the vector A*s + e

    return (A,t), s

pk, sk = keygen(k,q,f)

keys = {"secret":sk.tolist(), "public_A":pk[0].tolist(), "public_t":[a.tolist() for a in pk[1]]}
print(json.dumps(keys))