import os
import json
import numpy as np
from numpy.polynomial import polynomial as poly
from ring_lwe import parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly

def keygen(size, modulus, poly_mod):
    """Generate a public and secret keys
    Args:
        size: size of the polynoms for the public and secret keys.
        modulus: coefficient modulus.
        poly_mod: polynomial modulus.
    Returns:
        Public and secret key.
    """
    sk = gen_binary_poly(size)
    a = gen_uniform_poly(size, modulus)
    e = gen_normal_poly(size)
    b = polyadd(polymul(-a, sk, modulus, poly_mod), -e, modulus, poly_mod)
    return (b, a), sk

#encryption scheme parameters
n, q, t, poly_mod = parameters()
# Keygen
pk, sk = keygen(n, q, poly_mod)
keys = {"secret_key":str(sk.tolist()).replace(" ","").replace("[","").replace("]","").replace(",",""), "public_key":str(pk[0].tolist()+pk[1].tolist()).replace(" ","").replace("[","").replace("]","")}
print(json.dumps(keys))