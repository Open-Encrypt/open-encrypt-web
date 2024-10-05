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

    u = add_vec(mul_mat_vec_simple(transpose(A), r, f, q), e_1, q, f)
    v = sub_poly(polyadd(mul_vec_simple(t, r, f, q), e_2, q, f), m, q, f)

    return u, v

r = (np.random.random([k, n]) * 3).astype(int) - 1
e_1 = (np.random.random([k, n]) * 3).astype(int) - 1
e_2 = (np.random.random([n]) * 3).astype(int) - 1

if(len(argv) > 2):
    #get public ket from argv[1] ...
    pk_string = argv[1]
    pk_list = pk_string.split(",")
    A_list = np.int64(pk_list[:k*k*n])
    t_list = np.int64(pk_list[k*k*n:])
    A = np.reshape(A_list, (k, k, n)) #A is a matrix, a list of lists given as a single list of size k x k x n
    t = np.reshape(t_list, (k, n)) #t is a vector, a list of lists given as a single list of size k x n
    #get message from argv[2] ...
    message_string = argv[2]
    message_binary = [int(bit) for byte in bytearray(message_string, 'utf-8') for bit in format(byte, '08b')]
    num_blocks = len(message_binary) // n
    message_blocks = []
    for i in range(num_blocks):
        message_blocks.append(message_binary[i*n:(i+1)*n])
    m_b = np.array(message_blocks[0])
    #encrypt message using public key
    u, v = encrypt(A, t, m_b, f, q, r, e_1, e_2)
    #export the string
    uv_list = [a.tolist() for a in u] + [v.tolist()]
    uv_string = str(uv_list).replace("[","").replace("]","").replace(" ","")
    print(uv_string)