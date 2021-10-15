from Cryptodome.Util.number import getPrime, long_to_bytes, bytes_to_long
from sage.all import *
from sympy import *


class Merkle_Hellman():
    def __init__(self) -> None:
        self.pbkey = None
        self.pvkey = None

    def update_pbkey(self, pbkey):
        self.pbkey = pbkey

    def update_pvkey(self, pvkey):
        self.pvkey = pvkey

    def gen_super_inc_list(self, bit_length):
        super_inc_list = [getPrime(8)]
        for i in range(1, bit_length):
            super_inc_list += [nextprime(super_inc_list[i-1]
                                         << 1) + getrandbits(8)]
        return super_inc_list

    def gen_key(self, bit_length):
        super_inc_list = self.gen_super_inc_list(bit_length)
        B = nextprime(super_inc_list[-1] << 1)
        A = super_inc_list[-1] + getrandbits(8)
        pbkey = [(A*v) % B for v in super_inc_list]
        pvkey = (super_inc_list, A, B)
        self.update_pbkey(pbkey)
        self.update_pvkey(pvkey)
        return pbkey, pvkey

    def encrypt(self, message):

        return sum([k if m == '1' else 0 for k, m in zip(self.pbkey, message)])

    def decrypt(self, cip, pvkey):
        S = (invert(self.pvkey[1], self.pvkey[2])*cip) % self.pvkey[2]
        msg = ''
        for i in pvkey[0][::-1]:
            if i <= S:
                S -= i
                msg += '1'
            else:
                msg += '0'
        return msg


if __name__ == '__main__':
    mkhm = Merkle_Hellman()
    msg = b'SecretHere'
    pbkey, pvkey = mkhm.gen_key(len(bin(bytes_to_long(msg))[2:]))
    print('pbkey:', pbkey)
    cip = mkhm.encrypt(bin(bytes_to_long(msg))[2:])
    print(f'cip: {cip}')
    msg_decrypt = mkhm.decrypt(cip, pvkey)
    msg_decrypt = long_to_bytes(int(msg_decrypt[::-1], 2))
    assert msg == msg_decrypt
    print(msg_decrypt)
