import hmac
import hashlib


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    :param key:
    :param message:
    :return: 16进制序列
    """
    return (hmac.new(key, message, digestmod=hashlib.sha256).digest())
