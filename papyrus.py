import math
import hashlib
import hmac

def hh(*argv):
	m = hashlib.sha512()
	for arg in argv:
		m.update(arg)
	return m

login = "1234"
token = "f38230d198d973fe858999ca905ed52b090b02a7897fad9fbc99539b69c4fe26"

N = 0xac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73
g = 0x2
k = 0x5e195bdcd2ebc0dd886598590b5274f983a15a8b145dba693f0b4244330f62c2765921ca09be6eb7d0679faca9d84cf448d42d627e42c94edaed2ddfb485f5b2
salt = 0x8ed0372079856c404ba9ccf57ce4a9158ccbd43f845733feeae8048a8714dcce.to_bytes(length=32, byteorder='big')
password = b'\x00\x01\x02\x03'

x = int(hh(salt, password).hexdigest(), 16)
v = pow(g, x, N)
print(f'Verifier: {v:x}')

a = 0x2725de8565439cef24b67525a89ba270295ce20d11702d0d495b2a532f957a092b2e0187848803b5fb2761131cba7a087d9fef91d4d546b6fee47eee3b3a00e072529be1c0337651dfb53d26697d51ddda89e62044635cb84f3a23112e5f2b4647148706a99d6e432806f3c6e2bf8aa148988f1d3343a40847803d74fcc263d301f0596a7cd30703472f8aa7787a8d100670a9144144c10221355b3cdd82396145fd595f9ad3718ff871c761e495ec2314285e0f95246e7bcf4ebf06f5956fd9c17394f9f92dcaea7d8942e2975c194e425dce5400e077f0c00c0ea7f951712ac034093ba8d1fb3ef93b37301d900c34013b3eba5b845c2ad2f8cc5501c0d573
A = pow(g, a, N)
print(f'A: {A:x}')

# b = 0xed951a6bc447b4ff665c16fbd6e6640d0a70778911985351793f5136d04acda88384ed208cafd95051df25077f2fb73e2fc5794aa09210840978a6d0d4b462883513ae3d1c3a6c899cac83c3ad3b8599cd2da76426b0a94341e41bf17a36d7c45b431f216c93a8cc60b3e0870705f2328dc9573ff50ed519250b39bb4cdc3c9427c47ae5369492f755929adea532b86afb18ff21694dbb2a0df295986f9a784327321a4659d5e45d7be140580977803762f1707551dd3bf675d94d971886d5786091e9aa45228ce9a03bbc4fa635f41671bd6b10c47df58f358bfdd1782925795d24350281980fb0ad1157b1a1fd247a4be069d07bf033b63952f78980e248ee
# B = (pow(g, b, N) + (k*v % N)) % N
B = 0x8c482014d72e8b91eb17df6ff9972baf4cb93b60aba8a165d8b5c12038ff742e1f36c34ce34bc374a9b237b46cf492b39681252f0426d2d73ffc28d11fca9a86c83c9c05a1cde0cd62f9531e6ec14e41a277d1e048986c178559e2e9de5e9dd2d33d7ba269c3f73eb9a778300794bcbd1755a41603274484f7d0de23af2ef54da9a738e891622b9b2b215f0bd58fe1c98de091539cdf23c82472cd7629638296d22cec94f8f7ffad6084e8d84924b74e914bbb932103ce986cc74258a5d71e17f144a57f4e7f06a4896c5692a4fb767921d5347bd91252af6dc871d566806f9c518bd12ff900ffa81bf888c0a54bbae3b8c76d2e9a766516258f5503d206e582

m = hashlib.sha512()
m.update(A.to_bytes(length=256, byteorder='big'))
m.update(B.to_bytes(length=256, byteorder='big'))
u = int(m.hexdigest(), 16)

res1 = a + u*x
print(f'a + u * x: {res1:x}')

res2 = (B - k * pow(g, x, N)) % N
print(f'B - k * g^x: {res2:x}')

res = pow(res2, res1, N)
print(f'key before hash: {res:x}')

# res1 = pow(v, u, N)
# print(f'v^u: {res1:x}')

# res2 = res1 * A % N
# print(f'v^u * A: {res2:x}')

# res = pow(res2, b, N)
# print(f'key_before_hash: {res:x}')

m2 = hashlib.sha512()
m2.update(res.to_bytes(length=256, byteorder='big'))
session_key = m2.digest()
print(f'Key: {m2.hexdigest()}')

tmp = int(hh(N.to_bytes(length=256, byteorder='big')).hexdigest(), 16) ^ int(hh(g.to_bytes(length=1, byteorder='big')).hexdigest(), 16)
# print(f'TMP: {tmp:x}')

key_proof = hh(tmp.to_bytes(length=64, byteorder='big'), hh(bytes(login, 'ascii')).digest(), salt, A.to_bytes(length=256, byteorder='big'), B.to_bytes(length=256, byteorder='big'), session_key).hexdigest()
print(f'Proof: {key_proof}')


msg = '{"msg":"Hello"}'


hm = hmac.new(session_key, bytes(msg, 'utf8'), hashlib.sha512)
sig = hm.hexdigest()
print(f'Sig: {sig}')

