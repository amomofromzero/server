import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_gcm_encrypt(key: bytes, iv: bytes, additional_data: bytes, plaintext: bytes, record_num: int = None) -> (
        bytes, bytes):
    """
    aes_gcm算法加密数据
    :param key:
    :param iv:
    :param additional_data: 用于生成authtag，证明信息没有被修改过
    :param plaintext: 要加密的内容
    :return:返回加密的信息和authtag
    """
    if record_num is not None:
        iv = int.to_bytes(int.from_bytes(iv, "big") ^ record_num, 12, "big")
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(additional_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext, encryptor.tag


def aes_gcm_decrypt(key: bytes, iv: bytes, addition_data: bytes, ciphertext: bytes, tag: bytes,
                    record_num: int = None) -> bytes:
    """
    aes_gcm算法解密数据
    :param key:
    :param iv:
    :param addition_data:用于生成authtag来与输入的tag进行比较，证明信息没有被修改过
    :param ciphertext:加密的内容
    :param tag:证明信息没有被修改过
    :return:解密后的数据
    """
    try:
        if record_num is not None:
            iv = int.to_bytes(int.from_bytes(iv, "big") ^ record_num, 12, "big")
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(addition_data)

        return decryptor.update(ciphertext) + decryptor.finalize()
    except cryptography.exceptions.InvalidTag:  # 验证失败
        return None
