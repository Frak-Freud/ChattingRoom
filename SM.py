import hashlib
from base64 import b64encode, b64decode
from gmssl.utils import PrivateKey
from gmssl import sm2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import string
import random

BLOCK_SIZE = 16


def my_keys():
    # 字符串
    data = string.ascii_letters + string.digits
    # 随机长度k (1<= k <=32)
    AES_key = ''
    for _ in range(16):
        AES_key += data[random.randint(0, len(data) - 1)]
    priKey = PrivateKey()
    pubKey = priKey.publicKey()
    return AES_key, pubKey.toString(compressed=False), priKey.toString()


# sm2加密
def encrypt(info, sm2_crypt):
    info = sm2_crypt.encrypt(info.encode())
    info = b64encode(info).decode()
    return info


# sm2解密
def decrypt(info, sm2_crypt):
    missing_padding = 4 - len(info) % 4
    if missing_padding:
        info += '=' * missing_padding
    decode_info = b64decode(info.encode())  # 通过base64解码成二进制bytes
    decode_ = sm2_crypt.decrypt(decode_info).decode()
    return decode_


def Enc_and_sign(Message, AESKey, priKey_of_me):
    # 这一步生成这个用户此次的公钥以及私钥
    SKey = priKey_of_me
    sm2_self = sm2.CryptSM2(public_key='', private_key=SKey)
    sign = sm2_self.sign(hashlib.md5(Message.encode()).hexdigest().encode(), hex(random.randint(1, 100)))
    info = Message + '$%' + sign
    # 拼接明文和加密后的HASH
    aes = AES.new(AESKey.encode(), AES.MODE_ECB)
    en_text = aes.encrypt(pad(info.encode(), BLOCK_SIZE))
    return en_text


def Dec_and_verify(ciphertext, AESKey, pubKey_of_other):
    AESKey_encode = AESKey.encode()
    aes = AES.new(AESKey_encode, AES.MODE_ECB)  # 创建一个aes对象
    plaintext = aes.decrypt(ciphertext)
    plaintext = unpad(plaintext, BLOCK_SIZE).decode()
    index = plaintext.find('$%')
    if index:
        # 找出标志符位置
        message = plaintext[:index]
        hash_enc = plaintext[index + 2:]
        message_hash = hashlib.md5(message.encode()).hexdigest().encode()
        sm2_verify = sm2.CryptSM2(private_key='', public_key=pubKey_of_other)
        verify = sm2_verify.verify(hash_enc, message_hash)
        # 通过完整性检验
        if verify:
            return message
        # 未通过
        else:
            return False
