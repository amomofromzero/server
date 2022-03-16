import hashlib

from hkdf import hkdf_expand

empty_hash = bytes.fromhex(hashlib.sha256().hexdigest())
zero_key = b"\x00" * 32


def hkdf_expand_label(key: bytes, label: bytes, context: bytes = b"", length: int = 32, hash=hashlib.sha256) -> bytes:
    """
    :param key:
    :param label:
    :param context:
    :param length:生成的位数
    :param hash:hash算法
    :return:返回length长度的密钥
    """
    label_len = len(label) + 6
    context_len = len(context)
    info = bytes.fromhex(f"{hex(length)[2:]:0>4}") + bytes.fromhex(
        f"{hex(label_len)[2:]:0>2}") + b"tls13 " + label + bytes.fromhex(f"{hex(context_len)[2:]:0>2}") + context

    return hkdf_expand(key, info, length, hash)
