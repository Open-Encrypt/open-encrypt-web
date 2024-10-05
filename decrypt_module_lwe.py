from module_lwe import parameters, mul_vec_simple
from ring_lwe import sub_poly
import numpy as np
from sys import argv

np.random.seed(0xdeadbeef)

#get module-LWE parameters
n, q, f, k = parameters()

def decrypt(s, u, v, f, q):
  """Decrypt a ciphertext (u,v)
    Args:
        s: secret key
        u: first component of cipher text
        v: second component of cipher text
        f: polynomial modulus
        q: modulus
    Returns:
        Decrypted message m_b.
  """
  m_n = sub_poly(v, mul_vec_simple(s, u, f, q), q, f)

  half_q = int(q / 2 + 0.5)
  def round(val, center, bound):
    dist_center = np.abs(center - val)
    dist_bound = min(val, bound - val)
    return center if dist_center < dist_bound else 0

  m_n = list(map(lambda x: round(x, half_q, q), m_n))
  m_b = list(map(lambda x: x // half_q, m_n))
  
  return m_b

if(len(argv) >  2):
    #get secret key from argv[1]
    sk_string = argv[1]
    s_array = np.int64(sk_string.split(","))
    s = np.reshape(s_array,(k,n))
    #get the ciphertext string and recover u, v
    ciphertext_string = argv[2]
    ciphertext_list = ciphertext_string.split(",")
    u_array = np.int64(ciphertext_list[:k*n])
    v_array = np.int64(ciphertext_list[k*n:])
    u = np.reshape(u_array, (k,n))
    v = np.reshape(v_array, (n))
    #decrypt the ciphertext u, v with secret key s
    m_b = decrypt(s, u, v, f, q) 
    #export the decrypted message
    print(m_b)