from enum import Enum
import random

"""
定义TLS协议中的相关变量值和协议结构
修改日期 2022 02 16
"""


class TLSType(Enum):
    change_cipher_spec = b"\x14"  # 20
    alert = b"\x15"  # 21
    hand_shake = b"\x16"  # 22
    application_data = b"\x17"  # 23


class TLSVersion(Enum):
    v1 = b"\x03\x01"
    v2 = b"\x03\x03"


class HandShakeType(Enum):
    client_hello = b"\x01"  # 1
    server_hello = b"\x02"  # 2
    new_session_ticket = b"\x04"  # 4
    encrypted_extensions = b"\x08"  # 8
    certificate = b"\x0b"  # 11
    server_key_exchange = b"\x0c"  # 12
    server_hello_done = b"\x0e"  # 14
    certificate_verify = b"\x0f"  # 15
    client_key_exchange = b"\x10"  # 16
    handshake_finished = b"\x14"  # 20


class AlertLevel(Enum):
    warning = b"\x01"  # 1
    fatal = b"\x02"  # 2


class AlertDescription(Enum):
    close_notify = b"\x00"  # 0
    unexpected_message = b"\x0a"  # 10
    bad_record_mac = b"\x14"  # 20
    record_overflow = b"\x16"  # 22
    handshake_failure = b"\x28"  # 40
    bad_certificate = b"\x2a"  # 42
    unsupported_certificate = b"\x2b"  # 43
    certificate_revoked = b"\x2c"  # 44
    certificate_expired = b"\x2d"  # 45
    certificate_unknown = b"\x2e"  # 46
    illegal_parameter = b"\x2f"  # 47
    unknown_ca = b"\x30"  # 48
    access_denied = b"\x31"  # 49
    decode_error = b"\x32"  # 50
    decrypt_error = b"\x33"  # 51
    protocol_version = b"\x46"  # 70
    insufficient_security = b"\x47"  # 71
    internal_error = b"\x50"  # 80
    inappropriate_fallback = b"\x56"  # 86
    user_canceled = b"\x5a"  # 90
    missing_extension = b"\x6d"  # 109
    unsupported_extension = b"\x6e"  # 110
    unrecognized_name = b"\x70"  # 112
    bad_certificate_status_response = b"\x71"  # 113
    unknown_psk_identity = b"\x73"  # 115
    certificate_required = b"\x74"  # 116
    no_application_protocol = b"\x78"  # 120


class CipherSuites(Enum):
    Reserved_GREASE = b"\xba\xba"
    TLS_AES_128_GCM_SHA256 = b"\x13\x01"
    TLS_AES_256_GCM_SHA384 = b"\x13\x02"
    TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = b"\xc0\x2b"
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = b"\xc0\x2f"
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = b"\xc0\x2c"
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = b"\xc0\x30"
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = b"\xcc\xa9"
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = b"\xcc\xa8"
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = b"\xc0\x13"
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = b"\xc0\x14"
    TLS_RSA_WITH_AES_128_GCM_SHA256 = b"\x00\x9c"
    TLS_RSA_WITH_AES_256_GCM_SHA384 = b"\x00\x9d"
    TLS_RSA_WITH_AES_128_CBC_SHA = b"\x00\x2f"
    TLS_RSA_WITH_AES_256_CBC_SHA = b"\x00\x35"


class ExtensionName(Enum):
    ServerName = b"\x00\x00"
    SupportedGroups = b"\x00\x0a"
    SignatureAlgorithms = b"\x00\x0d"
    KeyShare = b"\x00\x33"
    PSKKeyExchangeModes = b"\x00\x2d"
    SupportedVersions = b"\x00\x2b"


client_TLS_struct = {"TLS":  # 用于解析
                         {"TLSType": (1, [i.value for i in TLSType]),
                          "TLSVersion": (2, [i.value for i in TLSVersion]),
                          "Length": (2, None),
                          "TLSContent": (None, None)}}

server_TLS_struct = {"TLS":  # 用于发送
                         {"TLSType": (1, TLSType.hand_shake.value),
                          "TLSVersion": (2, TLSVersion.v2.value),
                          "Length": (2, None),
                          "TLSContent": (None, None)}}

hand_shake_struct = {"HandShake":  # 用于解析，TLS协议之下
                         {"HandShakeType": (1, [i.value for i in HandShakeType]),
                          "Length": (3, None),
                          "HandShakeContent": (None, None)}}

client_hello_struct = {"ClientHello":  # 属于hand_shake协议
                           {"Version": (2, TLSVersion.v2.value),
                            "Random": (32, None),
                            "SessionIDLength": (1, None),
                            "SessionID": (None, None),
                            "CipherSuitesLength": (2, None),
                            "CipherSuites": (None, [c.value for c in CipherSuites]),
                            "CompressionMethodsLength": (1, None),
                            "CompressionMethods": (None, None),
                            "ExtensionsLength": (2, None),
                            "Extensions":
                                [{"ExtensionName": (2, [i.value for i in ExtensionName]),
                                  "ExtensionLength": (2, None),
                                  "ExtensionContent": (None, None)}]}}

server_hello_struct_with_handshake = {"ServerHelloHandShake":  # 带handshake的serverhello，方便使用
                                          {"HandShakeType": (1, HandShakeType.server_hello.value),
                                           "Length": (3, None),
                                           "ServerHello":
                                               {"Version": (2, TLSVersion.v2.value),
                                                "Random": (32, None),
                                                "SessionIDLength": (1, None),
                                                "SessionID": (None, None),
                                                "CipherSuites": (2, CipherSuites.TLS_AES_128_GCM_SHA256.value),
                                                "CompressionMethods": (1, b"\x00"),
                                                "ExtensionsLength": (2, None),
                                                "Extension":
                                                    {"SupportedVersions":
                                                         {"SupportedVersions": (2, b"\x00\x2b"),
                                                          "SupportedVersionsLength": (2, b"\x00\x02"),
                                                          "Version": (2, b"\x03\x04")},
                                                     "KeyShare":
                                                         {"KeyShare": (2, b"\x00\x33"),
                                                          "KeyShareLength": (2, b"\x00\x24"),
                                                          "x25519": (2, b"\x00\x1d"),
                                                          "PublicKeyLength": (2, b"\x00\x20"),
                                                          "PublicKey": (32, None)}}}}}

client_change_cipher_spec_struct = {"ChangeCipherSpec":  # 用于解析,是TLSStruct具体化
                                        {"TLSType": (1, TLSType.change_cipher_spec.value),
                                         "TLSVersion": (2, TLSVersion.v2.value),
                                         "Length": (2, None),
                                         "ClientKeyExchange": (None, None)}}

server_change_cipher_spec_struct_with_tls = {"ChangeCipherSpec":  # 用于解析,是TLSStruct具体化
                                                 {"TLSType": (1, TLSType.change_cipher_spec.value),
                                                  "TLSVersion": (2, TLSVersion.v2.value),
                                                  "Length": (2, None),
                                                  "ClientKeyExchange": (1, b"\x01")}}

alert_struct_with_tls = {"Alert":
                             {"TLSType": (1, TLSType.alert.value),
                              "TLSVersion": (2, TLSVersion.v2.value),
                              "Length": (2, None),
                              "AlertMessage":
                                  {"Level": (1, [a.value for a in AlertLevel]),
                                   "Description": (3, [a.value for a in AlertDescription])}}}
alert_struct = {"Alert":
                    {"Level": (1, [a.value for a in AlertLevel]),
                     "Description": (3, [a.value for a in AlertDescription])}}

tls_application_data_struct = {"ApplicationDataStruct":  # 用于解析和发送
                                   {"TLSType": (1, TLSType.application_data.value),
                                    "TLSVersion": (2, TLSVersion.v2.value),
                                    "Length": (2, None),
                                    "EncrypteData": (None, b"\x00")}}

encrypted_extensions_struct = {"EncryptedExtensionsStruct":
                                   {"HandShakeType": (1, HandShakeType.encrypted_extensions.value),
                                    "Length": (3, None),
                                    "ExtensionsLength": (2, b"\x00\x00")
                                    }}

server_certificate_handshake_struct = {"Certificate":  # 向客户端发送证书
                                           {"HandshakeType": (1, HandShakeType.certificate.value),
                                            "Length": (3, None),
                                            "_container":
                                                {"Request Context": (1, b"\x00"),
                                                 "CertificateLength": (3, None),
                                                 "Certificate":
                                                     {"CertificateLength": (3, None),
                                                      "Certificate": (None, None),
                                                      "CertificateExtensionsLength": (2, b"\x00\x00")}}}}

server_certificate_verify_struct = {"ServerCertificateVerify":
                                        {"HandshakeType": (1, HandShakeType.certificate_verify.value),
                                         "Length": (3, None),
                                         "Signature":
                                             {"reservedvalue": (None, b"\x08\x04"),
                                              "SignatureLength": (2, None),
                                              "Signature": (None, None)}}}

server_handshake_finished_struct = {"ServerHandshakeFinishedStruct":
                                        {"HandShakeType": (1, HandShakeType.handshake_finished.value),
                                         "Length": (3, None),
                                         "VerifyData": (None, None)}}

client_handshake_finished_struct = {"ClientHandshakeFinishedStruct":
                                        {"HandShakeType": (1, HandShakeType.handshake_finished.value),
                                         "Length": (3, None),
                                         "VerifyData": (None, None)}}

client_hello_public_keyshare_struct = {"KeyShare":
                                           {"Length": (2, None),
                                            "group": [
                                                {"Type": (2, None),
                                                 "Length": (2, None),
                                                 "Content": (None, None)}]}}

client_newSession_ticket_with_handshake_struct = {"NewSessionTicket":  # 用于解析，包括握手协议部分
                                                      {"HandshakeType": (1, HandShakeType.new_session_ticket.value),
                                                       "Length": (3, None),
                                                       "NewSessionTicket":
                                                           {"LifeTimeHint": (4, None),
                                                            "SessionTicketLength": (2, None),
                                                            "SessionTicket": (None, None)}}}

server_newSession_ticket_with_handshake_struct = {"NewSessionTicketHandShake":  # 用于解析，包括握手协议部分
                                                      {"HandshakeType": (1, HandShakeType.new_session_ticket.value),
                                                       "Length": (3, None),
                                                       "NewSessionTicket":
                                                           {"LifeTimeHint": (4, bytes.fromhex(f"{hex(3600)[2:]:0>8}")),
                                                            # 默认时长为1小时
                                                            "TicketAgeAdd": (4, bytes.fromhex(
                                                                f"{hex(random.randint(0, 2 ** 32))[2:]:0>8}")),
                                                            "TicketNonce":
                                                                {"NonceLength": (1, None),
                                                                 "NonceValue": (None, None)},
                                                            "SessionTicket":
                                                                {"SessionTicketLength": (2, None),
                                                                 "SessionTicket": (None, None)},
                                                            "TicketExtensions":
                                                                {"TicketExtensionsLength": (2, None),
                                                                 "EarlyData":
                                                                     {"TYPE": (2, b"\x00\x2a"),
                                                                      "Length": (2, None),
                                                                      "Value": (None, b"\x00\x00\x40\x00")}}}}}
