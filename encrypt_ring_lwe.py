import numpy as np
from numpy.polynomial import polynomial as poly
from ring_lwe import parameters, polymul, polyadd, gen_binary_poly, gen_uniform_poly, gen_normal_poly
from sys import argv

#scheme's parameters
n, q, t, poly_mod = parameters()

def encrypt(pk, size, q, t, poly_mod, pt):
    """Encrypt an integer or list of integers.
    Args:
        pk: public-key.
        size: size of polynomials.
        q: ciphertext modulus.
        t: plaintext modulus.
        poly_mod: polynomial modulus.
        pt: integer to be encrypted.
    Returns:
        Tuple representing a ciphertext.      
    """
    # encode pt into a plaintext polynomial if pt is an int, otherwise encode as a full polynomial
    if isinstance(pt,int):
        m = np.array([pt] + [0] * (size - 1), dtype=np.int64) % t
    elif isinstance(pt,list):
        m = np.array(pt,dtype = np.int64) % t
        m.resize(n)
    else:
        print("pt should be int or list of ints")
    delta = q // t
    scaled_m = delta * m  % q
    e1 = gen_normal_poly(size)
    e2 = gen_normal_poly(size)
    u = gen_binary_poly(size)
    ct0 = polyadd(
            polyadd(
                polymul(pk[0], u, q, poly_mod),
                e1, q, poly_mod),
            scaled_m, q, poly_mod
        )
    ct1 = polyadd(
            polymul(pk[1], u, q, poly_mod),
            e2, q, poly_mod
        )
    return (ct0, ct1)

if(len(argv) > 2):
    #get the public key from the string and format as two arrays
    pk_string = argv[1]
    pk_arr = [int(coeff) for coeff in pk_string.split(',')]
    pk_b = np.int64(pk_arr[:n])
    pk_a = np.int64(pk_arr[n:])
    pk = (pk_b,pk_a)
    #define the integers to be encrypted
    #note bytes are 8 bits, so message_int < 2^8 = t = plaintext modulus, which can be modified
    message = argv[2]
    message_bytes = [format(x, 'b') for x in bytearray(message, 'utf-8')]
    message_ints = [int(message_byte,2) for message_byte in message_bytes]
    message_blocks = []
    for i in range(0,len(message_ints),n):
        message_blocks.append(message_ints[i:i+n])
    #encrypt each integer message_int
    ciphertext_list = []
    for message_block in message_blocks:
        ciphertext = encrypt(pk, n, q, t, poly_mod, message_block)
        ciphertext_list += ciphertext[0].tolist() + ciphertext[1].tolist()
    ciphertext_string = str(ciphertext_list).replace('[','').replace(']','').replace(' ','')
    print(ciphertext_string)