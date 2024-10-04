from ring_lwe import polyadd, polymul
import numpy as np

def parameters():
    # polynomial modulus degree
    n = 2**2
    # ciphertext modulus
    q = 67
    # polynomial modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])
    #module rank
    k = 2
    return (n,q,poly_mod,k)

def add_vec(v0, v1, q):
  assert(len(v0) == len(v1)) # sizes need to be the same

  result = []

  for i in range(len(v0)):
    result.append(polyadd(v0[i], v1[i], q, f))
  
  return result


def mul_vec_simple(v0, v1, f, q):
  assert(len(v0) == len(v1)) # sizes need to be the same

  degree_f = len(f) - 1
  result = [0 for i in range(degree_f - 1)]

  # textbook vector inner product
  for i in range(len(v0)):
    result = polyadd(result, polymul(v0[i], v1[i], q, f), q, f)
  
  return result


def mul_mat_vec_simple(m, a, f, q):
  result = []
  
  # textbook matrix-vector multiplication
  for i in range(len(m)):
    result.append(mul_vec_simple(m[i], a, f, q))
  
  return result

#transpose of a matrix
def transpose(m):
  result = [[None for i in range(len(m))] for j in range(len(m[0]))]

  for i in range(len(m)):
    for j in range(len(m[0])):
      result[j][i] = m[i][j]
  
  return result