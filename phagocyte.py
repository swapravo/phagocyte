#! /usr/bin/python3


"""
A self replicating program that attaches itself onto files and
encrypts them, producing executables that can decrypt themselves
to produce the original file. It has no dependencies.

ChaCha20 implementation has been taken from 
https://github.com/pts/chacha20 and is by pts@fazekas.hu
Please note that it does NOT use any authenticators
like Poly1305.
"""


from getpass import getpass
from os import urandom, rename
from hashlib import pbkdf2_hmac
from struct import pack, unpack
from argparse import ArgumentParser
from base64 import b85encode, b85decode as decode


def yield_chacha20_xor_stream(key, iv, position=0):
  """Generate the xor stream with the ChaCha20 cipher."""
  if not isinstance(position, int):
    raise TypeError
  if position & ~0xffffffff:
    raise ValueError('Position is not uint32.')
  if not isinstance(key, bytes):
    raise TypeError
  if not isinstance(iv, bytes):
    raise TypeError
  if len(key) != 32:
    raise ValueError
  if len(iv) != 8:
    raise ValueError

  def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)

  def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)

  ctx = [0] * 16
  ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
  ctx[4 : 12] = unpack('<8L', key)
  ctx[12] = ctx[13] = position
  ctx[14 : 16] = unpack('<LL', iv)
  while 1:
    x = list(ctx)
    for i in range(10):
      quarter_round(x, 0, 4,  8, 12)
      quarter_round(x, 1, 5,  9, 13)
      quarter_round(x, 2, 6, 10, 14)
      quarter_round(x, 3, 7, 11, 15)
      quarter_round(x, 0, 5, 10, 15)
      quarter_round(x, 1, 6, 11, 12)
      quarter_round(x, 2, 7,  8, 13)
      quarter_round(x, 3, 4,  9, 14)
    for c in pack('<16L', *(
        (x[i] + ctx[i]) & 0xffffffff for i in range(16))):
      yield c
    ctx[12] = (ctx[12] + 1) & 0xffffffff
    if ctx[12] == 0:
      ctx[13] = (ctx[13] + 1) & 0xffffffff


def chacha20_encrypt(data, key, iv=None, position=0):
  """Encrypt (or decrypt) with the ChaCha20 cipher."""
  if not isinstance(data, bytes):
    raise TypeError

  return bytes(a ^ b for a, b in
      zip(data, yield_chacha20_xor_stream(key, iv, position)))


def encode(bin_data):
	return str(b85encode(bin_data), 'ascii')


def kdf(password, salt):
	"""
	feel free to tweak the parameters
	if you know what you are doing
	"""
	return pbkdf2_hmac('sha256', bytes(password, 'utf-8'), salt, 1000000)


def source():
	"""
	return only the source code, even if
	the program has data attached onto it
	"""
	with open(__file__, 'r') as me:
		return me.read().split('\ndata = r"""\n')[0]


def replicate():
	with open('worm_' + encode(urandom(4)) + '.py', 'w') as twin:
		twin.write(source())


def encrypt(files):
	iv = urandom(8)
	salt = urandom(16)
	key = kdf(password, salt)
	iv_string = encode(iv) # always 10 ascii chars long
	salt_string = encode(salt) # always 20 ascii chars long

	for _file in files:
		with open(_file, 'rb') as fo:
			data = fo.read()
		with open(_file, 'w') as fo:
			fo.write(source() + '\ndata = r"""\n')
			fo.write(encode(chacha20_encrypt(data, key, iv)))
			fo.write(iv_string + salt_string + '\n"""\n')


def decrypt():
	with open(__file__, 'r') as me:
		data = me.read().split('\ndata = r"""\n')[1][:-5]
	salt = decode(data[-20:])
	iv = decode(data[-30:-20])
	key = kdf(password, salt)
	data = chacha20_encrypt(decode(data[:-30]), key, iv)
	if not args.s:
		rename(__file__, __file__+'.py')
	with open(__file__, 'wb') as _file:
		_file.write(data)


password = None
data = None

parser = ArgumentParser(description="\
	Phagocyte is a self replicating program that attaches itself \
	onto files and encrypts them, producing executables.", \
	epilog="Warning: You will lose your data if you enter the \
	wrong password with the -s flag enabled.\nAvailable under \
	the MIT license. \u00a9 Swapravo Sinha Roy : swapravo.github.io")
parser.add_argument('-r', action='store_true', help='replicate the program')
parser.add_argument('-e', nargs = '+', help='encrypt files')
parser.add_argument('-d', action='store_true', help='decrypt itself')
parser.add_argument('-s', action='store_true', help='delete the executable after decryption')
args = parser.parse_args()

if args.r:
	replicate()

if args.e:
	password = getpass()
	encrypt(args.e)

if args.d:
	password = getpass()
	decrypt()
