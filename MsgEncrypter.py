import random


class RsaKeys(object):
    '''
    A class implementation of the RSA key
    generation that takes p and q and has a
    method call Keys() to return ((e, n), d).
    Note that all methods are private by
    default except for the Keys() method.
    >>>RsaKeys(23, 47).Keys()
    ((59, 1081), 953)
    '''

    def __init__(self, p=3251, q=62683):
        self.p = p
        self.q = q
        self.phi = self._find_phi()
        self.pubkey = self._Find_PublicKey_e()
        self.privkey = self._Find_Private_Key_d()

    def _find_phi(self):
        '''
        Totient function. Though I didn't know
        that's what it was called when I first
        wrote it. Helper function that takes args
        p and q and returns phi.
        '''
        phi = (self.p - 1) * (self.q - 1)
        # this checks to make sure phi is larger than
        # the value of the last ascii character.
        assert phi > 127
        return phi

    def _Find_PublicKey_e(self):
        '''
        Takes args p and q and returns
        a compatible value of e and n. This
        becomes expensive for large values
        of p and q. I have disabled it.
        '''
        n = self.p * self.q
        # this makes sure e starts out as a random integer
        # from 1 to the floor half the product of p and q. From there
        # this loop iterates up to the product of (p and q) - 1
        # until it finds the first value for e that is coprime
        # to the totient of p and q.
        for e in range(random.randint(1, n // 2), n - 1):
            if self._gcd(e, self.phi) == 1:
                return e, n

    def _Find_Private_Key_d(self):
        '''
        Args e and phi are passed from
        class in the context of e mod phi
        and returns their modular inverse.
        '''
        e, _ = self.pubkey
        d = self._egcd(e) % self.phi
        if d < 0:
            d += self.phi
        return d

    def _gcd(self, b, m):
        '''
        Takes two integers, b and m, and
        returns their greatest common divisor.
        '''
        # while the modulus is not zero, b assigns to m,
        # m assigns to b % m
        while m != 0:
            b, m = m, b % m
        return b

    def _egcd(self, e):
        '''
        Helper function to compute the
        modular inverse of e and phi. Takes
        arguments b and m.
        '''
        a, b = e, self.phi
        x, x0 = 0, 1
        y, y0 = 1, 0
        while b > 0:
            q = a // b
            a, b = b, a % b
            x, x0 = x0 - q * x, x
            y, y0 = y0 - q * y, y
        return x0

    def Keys(self):
        '''
        Main method to return key values.
        Takes no arguments.
        '''
        return self.pubkey, self.privkey


class ProcessMessage(object):
    '''
    Takes the message string OR a list of binary
    strings as a single argument. Access attributes
    for utilization, no accessible methods. Please
    don't try to call the attributes.
    >>>msg = ProcessMessage('hello')
    >>>msg.bin_list
    ['1101000', '1100101', '1101100', ...]
    >>>msg.string
    'hello'
    '''

    def __init__(self, data):
        self.string = data
        self.ords = data
        if type(data) is str:
            self.ords = self._convert_text()
        elif type(data) is list:
            self.string = self._convert_num(self.ords)
        else:
            raise ValueError

    def _convert_text(self):
        '''
        Takes a string for argument, converts
        each letter to ascii number and returns
        a list of these numbers.
        '''
        return [ord(char) for char in self.string]

    def _convert_num(self, ord_list):
        '''
        Converts ords back to text.
        '''
        return ''.join([chr(n) for n in self.ords])


class Encryption(object):

    def __init__(self):
        pass

    def encode(self, data, pubkey):
        '''
        Takes args list of binaries and pubkey and
        uses 4, 6 and the FME method to encrypt the
        string. Returns a list of the encryption
        values.
        '''
        e, n = pubkey
        data = ProcessMessage(data).ords

        return [self._fme(M, e, n) for M in data]

    def decode(self, data, pubkey, privkey):
        e, n = pubkey
        d = privkey
        data = [self._fme(C, d, n) for C in data]
        return ProcessMessage(data).string

    def _fme(self, M, e, n):
        '''
        Takes a base, exponent, and modulus as arguments to
        calculate and return the modular exponent.
        '''
        if n == 1:
            return 0
        result = 1
        M = M % n
        while e > 0:
            if (e % 2 == 1):
                result = (result * M) % n
            e //= 2
            M = (M ** 2) % n
        return result


class Crack(object):

    def __init__(self, e, n):
        self.e, self.n = e, n

    def brute_force(self):
        # n is a number, return the smallest factor of n
        for i in range(2, self.n - 1):
            if self.n % i == 0:
                return i, self.n // i
        return False

    def crack_d(self):
        p, q = self.brute_force()
        phi = (p - 1) * (q - 1)
        a, b = self.e, phi
        x, x0 = 0, 1
        y, y0 = 1, 0
        while b > 0:
            q = a // b
            a, b = b, a % b
            x, x0 = x0 - q * x, x
            y, y0 = y0 - q * y, y
            d = x0 % phi
            if d < 0:
                d += phi
        return d, (p, q)


def select_encrypt():
    try:
        e, n = input('Enter public key for encryption:\n').strip(
            '(,)').split(',')
        pubkey = int(e), int(n)
        msg = str(input('Enter a message for encryption:\n'))
        C = Encryption().encode(msg, pubkey)
        print('\nMessage for transmission follows:')
        print(pubkey, C)
        run_again()
    except:
        print('\nExiting...')
        return


def select_decrypt():
    try:
        privkey = int(input('Enter your private key:\n'))
        e, n = input('Enter public key:\n').strip('(,)').split(',')
        pubkey = int(e), int(n)
        msg = str(input('Enter the message for decryption:\n'))
        msg = [int(i) for i in msg.strip('[,]').split(', ')]
        M = Encryption().decode(msg, pubkey, privkey)
        print('\nThe decrypted message is as follows:\n')
        print(M)
        run_again()
    except:
        print('\nExiting')
        return


def select_key():
    try:
        p, q = int(input('Press enter to use default primes or...\nenter your first prime.\n')), int(
            input('Enter your second prime.\n'))
    except:
        p, q = 0, 0
    if (p and q) == 0:
        print('Using default primes... will take approx 30 sec for a stronger key.')
        key = RsaKeys().Keys()
        print('Your Public Key is:', key[0])
        print('Your Private Key is:', key[1])
        print('Loss of Private Key will render encrypted messages unretreivable!')
        run_again()
    else:
        key = RsaKeys(p, q).Keys()
        print('Your Public Key is:', key[0])
        print('Your Private Key is:', key[1])
        print('WARNING! Loss of Private Key will render encrypted messages unretreivable!')
        run_again()


def select_break():
    try:
        pubkey = input('Enter public key:\n').strip('(,)').split(', ')
        e, n = pubkey
        e, n = int(e), int(n)
        privkey, primes = Crack(e, n).crack_d()
        print('The private key is {} and the constructor primes are {}'.format(
            privkey, primes))
    except:
        print('\nExiting...')
        return
    run_again()


def run_again():
    back = str(input('\nDo you wish to return to main menu or exit? (r/x) '))
    while back not in 'rx':
        back = str(input('Invalid entry. Do you wish to return menu? (r/x) '))
    if back == 'r':
        selector()
    else:
        print('\nExiting...')
        return


def selector():
    selection = str(input(
        'Encrypt a message, decrypt a message, generate a keypair, or try to break a pubkey? (e/d/k/b): ')).lower()
    while selection not in 'edkb':
        selection = str(input('Invalid entry. Choose from (e/d/k/b): '))
    if selection == 'e':
        select_encrypt()
    if selection == 'd':
        select_decrypt()
    if selection == 'k':
        select_key()
    if selection == 'b':
        select_break()


def main():
    selector()

if __name__ is '__main__':
    main()

main()