p = 29 # prime
for i in range(10):
    print(pow(p-1, i, p))

p = 29 # prime
for i in range(10):
     t = Mod(p-1, p) # sage code
     print(t**i)

p = 29 # prime
for i in range(10):
     t = sqrt(Mod(p-1, p)) # sage code
     print(t**i)

from Crypto.Util.number import long_to_bytes
long_to_bytes()

sqrt(Mod(p-1, p)) # sage code for t

# FLAG{M4yBe_i_N33d_70_checK_7he_0rDEr_OF_G}