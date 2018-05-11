# Shara Teresa González Mena A01205254
# Moisés Montaño Copca A01271656

# Examen final Seguridad Informática Parte 2

from Crypto.Cipher import AES
from Crypto import Random

iv = Random.new().read(AES.block_size)

print (iv)
