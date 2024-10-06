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
    #break into blocks of size k*n+n = (k+1)*n
    block_size = (k+1)*n
    num_blocks = len(ciphertext_list) // block_size
    message_binary = []
    for i in range(num_blocks):
      u_array = np.int64(ciphertext_list[i*block_size:i*block_size+k*n])
      v_array = np.int64(ciphertext_list[i*block_size+k*n:(i+1)*block_size])
      u = np.reshape(u_array, (k,n))
      v = np.reshape(v_array, (n))
      #decrypt the ciphertext u, v with secret key s
      m_b = decrypt(s, u, v, f, q) 
      #export the decrypted message
      message_binary += m_b
    # Group the bits back into bytes (8 bits each)
    byte_chunks = [''.join(str(bit) for bit in message_binary[i:i+8]) for i in range(0, len(message_binary), 8)]
    # Convert each binary string back into a character
    message_string = ''.join([chr(int(byte, 2)) for byte in byte_chunks])
    print(str(message_string).replace('[','').replace(']','').replace(' ',''))