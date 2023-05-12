from Crypto.Util.number import isPrime

def find_p():
    for a in range(70, 100):
        for b in range(70, 100):
            for c in range(70, 100):
                for d in range(70, 100):
                    for e in range(70, 100):
                        n = pow(2, a) * pow(3, b) * pow(7, c) * pow(11, d) * pow(13, e)
                        p = n + 1
                        bit_length = p.bit_length()
                        if bit_length == 1024:
                            if isPrime(p):
                                print(p)
                                return
if __name__ == '__main__':
    find_p()
# 152744294539980278765788801076585501079291523535506767726528521659770180869558164735520354233835785112664566361223221199010317411576452139281249651354892890084065538849953042358630895664091423884100199777813162378714287549397127837484641466570258023960655053217116819465388863584753232085018550501639251296257