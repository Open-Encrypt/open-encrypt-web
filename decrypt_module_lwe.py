from module_lwe import parameters, mul_vec_simple
from ring_lwe import sub_poly
import numpy as np
from sys import argv

np.random.seed(0xdeadbeef)

n, q, f, k = parameters()

def decrypt(s, u, v, f, q):
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
    s = np.int64([*sk_string])
    #get the ciphertext string
    ciphertext_string = argv[2]
    u, v = ...
    #decrypt the ciphertext u, v with secret key s
    m_b = decrypt(s, u, v, f, q) 
    #export the decrypted message
    print(m_b)