import numpy as np
import random
import json
from module_lwe import parameters, add_vec, mul_mat_vec_simple

np.random.seed(0xdeadbeef)

#load module-LWE parameters
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

#generate public, secret keys
pk, sk = keygen(k,q,f)

#convert lists of lists, arrays, etc. to string of comma separated ints
sk_string = str(sk.tolist()).replace("[","").replace("]","").replace(" ","")
A_string = str(pk[0].tolist()).replace("[","").replace("]","").replace(" ","")
t_string = str([a.tolist() for a in pk[1]]).replace("[","").replace("]","").replace(" ","")

#export keys as json
keys = {"secret":sk_string, "public_A":A_string, "public_t":t_string}
print(json.dumps(keys))