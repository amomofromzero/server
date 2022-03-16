from cryptography import exceptions
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding, types

"""
rsa_pss_rase_sha256签名和认证算法
修改日期 20220307
"""


def rsa_pss_rase_sha256_sign(private_key: types.PRIVATE_KEY_TYPES, message: bytes) -> bytes:
    """
    rsa_pss_rase_sha256签名算法，用于certificate verify
    :param private_key:certificate 私钥
    :param message: 要签名的内容
    :return:
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    return signature


def rsa_pss_rase_sha256_verify(public_key: types.PUBLIC_KEY_TYPES, message: bytes, signature: bytes) -> bool:
    """
    rsa_pss_rase_sha256验证算法，用于验证客户端
    :param public_key:certificate公钥
    :param message:要验证的信息
    :param signature:签名信息
    :return:成功返回true,失败返回false
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return True
    except exceptions.InvalidSignature:
        return False
