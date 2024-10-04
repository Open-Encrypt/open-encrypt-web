import numpy as np
from numpy.polynomial import polynomial as poly
from ring_lwe import parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly
from sys import argv

#scheme's parameters
n, q, t, poly_mod = parameters()

def decrypt(sk, size, q, t, poly_mod, ct):
    """Decrypt a ciphertext
    Args:
        sk: secret-key.
        size: size of polynomials.
        q: ciphertext modulus.
        t: plaintext modulus.
        poly_mod: polynomial modulus.
        ct: ciphertext.
    Returns:
        Integer representing the plaintext.
    """
    scaled_pt = polyadd(
            polymul(ct[1], sk, q, poly_mod),
            ct[0], q, poly_mod
        )
    decrypted_poly = np.round(scaled_pt * t / q) % t
    #return int(decrypted_poly[0])
    return [int(a) for a in decrypted_poly]

if(len(argv) > 2):
    #get the secret key from the string and format as array
    sk_string = argv[1]
    sk = np.int64([*sk_string])
    #get the ciphertext to be decrypted
    ciphertext_string = argv[2]
    ciphertext_array = np.int64(ciphertext_string.split(','))
    num_bytes = len(ciphertext_array) // (2*n)
    decrypted_message = ""
    for i in range(num_bytes):
        c0 = ciphertext_array[2*i*n:(2*i+1)*n]
        c1 = ciphertext_array[(2*i+1)*n:(2*i+2)*n]
        ct = (c0,c1)
        decrypted_poly = decrypt(sk, n, q, t, poly_mod,ct)
        decrypted_message += ''.join([chr(coeff) for coeff in decrypted_poly])
    print(decrypted_message)