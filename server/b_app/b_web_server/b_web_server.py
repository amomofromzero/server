import asyncio
import copy
import datetime
import hashlib
import socket
import time
import traceback
import re
import log
from concurrent.futures.process import ProcessPoolExecutor
import b_read_from_file
# 以下为自定义的相关算法和解析库
from b_analysis_httpRequest import analysis_httpRequest
from b_tls import *
from b_aes_gcm_encrypt import *
from b_hkdf import *
from b_hmac_sha256 import *
from b_rsa_pss_rase_sha256_sign import *

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from hkdf import hkdf_extract
from protocol_analysis import *

"""
https服务器
最后修改 2022 03 10
"""

# 基本设置
with  open("./b_app/b_web_server/web_data/web_certification/amomo.club.key", encoding="utf-8") as f:
    PRIVATE_KEY = load_pem_private_key(f.read().encode(), password=None)  # 获取证书私钥

with open("./b_app/b_web_server/web_data/web_certification/amomo.club_bundle.cer", "rb") as f:
    server_certificate_handshake_struct["Certificate"]["_container"]["Certificate"]["Certificate"] = (
        None, f.read())  # 装载证书

TASK_MAX_TIME = 5  # 每个任务默认的最长持续时间，超时后直接结束，避免资源浪费，可以根据任务具体调整，协程应尽量将任务分割为小任务，避免单一任务长期占用服务器
MAX_LISTENER_NUM = 20  # 最大同时监听数
CLIENT_ACESS_MAX_FREQUENCY = 20  # 大于这个频率，将加入黑名单
URL_HANLDERS = {re.compile(r"^/get_sharedFiles"): "get_sharedFiles_handeler",
                re.compile(r"^/"): "get_source_handler"}  # 每个请求对应的python命令
SEND_BYTES_NUM = 1024  # 每次发送的字节数,避免一个请求长期占用服务器资源
CURRENT_CLIENT_NUM = 0  # 当前用户数

# 初始化全局变量
BLACK_IP_LIST = set()  # 黑名单
LOG = log.LOG
EXECUTOR = ProcessPoolExecutor(5)
CLIENT_ACESS_INFO = {}  # 记录客户端IP的访问信息
FILE_CACHE = b_read_from_file.FILE_CACHE  # 文件缓存


def current_time() -> str:
    """
    输出当前时间
    :return: 当前时间
    """
    return datetime.datetime.now().strftime("%Y年 %m月 %d日 %H时 %M分 %S秒")


class _Client_Access_Information():
    """记录客户端(ip)访问频率等信息"""

    def __init__(self, ip, socket):
        self.ip = ip
        self.socket = socket
        self.frequency = 0  # 记录访问频率
        self.lastAccessTime = time.time()  # 记录最近访问时间

    def update(self):  # 再此访问，更新数据
        lt = self.lastAccessTime
        self.lastAccessTime = time.time()
        interval = self.lastAccessTime - lt  # 两次访问间隔时间
        if interval < 0.1:  # 访问间隔小于0.1秒
            self.frequency += 1  # 增加频率，可能会将本ip纳入黑名单
            if self.frequency > CLIENT_ACESS_MAX_FREQUENCY:  # 超过允许的访问频率，加入黑名单
                BLACK_IP_LIST.add(self.ip)
                LOG.log(f"{self.ip} 加入黑名单，清除其所有任务")
                for s in CLIENT_ACESS_INFO[self.ip]:  # 关闭本ip所有任务
                    s.socket.shutdown(2)
                    s.socket.close()
                del CLIENT_ACESS_INFO[self.ip]  # 从任务列表删除
        elif interval > 5:  # 访问间隔时间较长，可能不需要再链接
            LOG.log(f"{self.ip}:{self.socket.getpeername()[1]} 端口较长时间没有任务，断开连接")
            self.socket.shutdown(2)
            self.socket.close()
        else:
            self.frequency = max(0, self.frequency - interval)  # 如果访问间隔较长，则逐步降低访问频率，最低不低于0


def _update_client_access_info(ip, socket):
    """
    根据ip更新CLIENT_ACESS_INFO
    :param ip: ip地址
    """
    if ip in CLIENT_ACESS_INFO:  # 近期ip访问过
        if socket in CLIENT_ACESS_INFO[ip]:  # ip已经存在这个端口
            CLIENT_ACESS_INFO[ip][socket].update()
        else:
            CLIENT_ACESS_INFO[ip][socket] = _Client_Access_Information(ip, socket)

    else:  # 新的访问ip
        CLIENT_ACESS_INFO[ip] = {}
        CLIENT_ACESS_INFO[ip][socket] = _Client_Access_Information(ip, socket)  # 记录ip访问信息


def _clear():
    """清理僵尸任务"""
    try:
        for ip, sockets in CLIENT_ACESS_INFO:
            for s in sockets:
                s.update()
    except Exception as e:
        LOG.log(f"清理任务出错，正常现象，错误信息:{e}")


async def _http_request_hanlder(request):
    request = analysis_httpRequest(request)  # 解析http消息
    if request is None:  # 客户端返回空的字符，直接关闭
        return 'HTTP/1.1 404 Not Found\r\ncontent-type: text/html\r\n\r\n<head>\n<meta charset="UTF-8">\n服务器不能解析此请求，请核对输入的链接</head>'.encode(
            "utf-8")
    # 处理url
    url = request["url"]  # 解析http请求，获取url
    handler_found = False  # False没有找到网址对应的解析程序
    for r, h in URL_HANLDERS.items():  # r,h分别表示url和对应的处理方法,r是re.compile对象，用正则表达式解析网址
        if r.match(url):  # 找到处理函数
            handler_found = True
            exec(f"import {h}")  # 导入包，待完善，考虑load，动态重载
            func = eval(f"{h}.main")  # 对应的处理函数
            # 因为处理程序具有不确定性，可能时间较长，采用多进程，待完善，非计算密集型不需要多进程
            return await asyncio.get_event_loop().run_in_executor(EXECUTOR, func, request)

    if not handler_found:  # 没有找到对应函数
        return 'HTTP/1.1 404 Not Found\r\ncontent-type: text/html\r\n\r\n<head>\n<meta charset="UTF-8">\n服务器不能处理此请求，请核对输入的链接</head>'.encode(
            "utf-8")


async def _https_server(reader, writer):
    """
    处理https的请求，并返回结果
    :param reader:
    :param writer:
    :return:
    """
    socket = writer.get_extra_info("socket")  # 获取与客户端链接的socket
    addr, port = socket.getpeername()  # 获取客户端ip地址和端口

    if CURRENT_CLIENT_NUM > 5:  # 访问用户较多
        LOG.log(f"当前所有访问用户:{CLIENT_ACESS_INFO}")
        _clear()  # 尝试清除僵尸任务
        LOG.log(f"清理后所有访问用户:{CLIENT_ACESS_INFO}")

    _update_client_access_info(
        addr, socket)  # 可以理解为ip最近的交互时间，包括接受、发送消息，计算key或加密数据等，如果一段时间内，什么任务都没进行，则直接关闭，在await或者耗时较长的计算任务之前和之后使用
    try:
        # 待完善，记录客户端请求信息，同时校验之前的请求，对于超时的任务直接结束,每次await之前都应该有此检测
        if addr in BLACK_IP_LIST:
            LOG.log(f"{addr}:{port}在黑名单中")
            return

        hand_shake_hash = hashlib.sha256()  # 每次握手后更新hash
        client_handshake_is_finished = False  # 客户端是否发送client_handshake_finished

        # 每发送一次数据，对应的num+1，并于iv异或来进行加密
        client_handshake_record_num = 0
        server_handshake_record_num = 0
        client_application_record_num = 0
        server_application_record_num = 0

        while True:  # 不断接读取信息，解析tls协议
            _update_client_access_info(addr, socket)  # 更新ip最后交互的时间，用于之后清除僵尸任务

            try:
                data = await reader.readexactly(5)  # 期望收到tls，读取头四个字节，决定接下来接受的tls内容的长度
            except  asyncio.IncompleteReadError:
                LOG.log(f"{addr}:{port}客户端发送字节不足,发送的内容为 {await reader.read(5)} ")
                return

            try:
                data += await reader.readexactly(int.from_bytes(data[3:5], "big"))  # tls第3-4字节表示tls内容的长度
            except  asyncio.IncompleteReadError:
                LOG.log(f"{addr}:{port}客户端发送tls内容长度不符")
                return

            tls = Protocol(client_TLS_struct, data, strict=True)  # 解析tls协议
            if not tls:  # 不能解析TLS协议
                LOG.log(f'{addr}:{port}客户端tls协议解析失败')
                return

            tls_type = tls.parsed_content["TLS"]["TLSType"]

            if tls_type == TLSType.hand_shake.value:  # 发送的为握手协议
                hand_shake = Protocol(hand_shake_struct, tls.parsed_content["TLS"]["TLSContent"], strict=True)  # 解析握手协议
                if not hand_shake:  # 不能解析握手协议
                    LOG.log(f'{addr}:{port}客户端握手协议解析失败')
                    return

                hand_shake_type = hand_shake.parsed_content["HandShake"]["HandShakeType"]

                if hand_shake_type == HandShakeType.client_hello.value:
                    client_hello_handshake_data = tls.parsed_content["TLS"]["TLSContent"]
                    client_hello = Protocol(client_hello_struct,
                                            hand_shake.parsed_content["HandShake"]["HandShakeContent"],
                                            strict=True)  # 解析client_hello
                    if not client_hello:
                        LOG.log(f'{addr}:{port}客户端client_hello解析失败')
                        return

                    LOG.log(f'{addr}:{port}客户端发送client hello {current_time()}')

                    hand_shake_hash.update(client_hello_handshake_data)  # 跟新握手数据的hash

                    client_hello_random = client_hello.parsed_content["ClientHello"]["Random"]
                    client_session_id = client_hello.parsed_content["ClientHello"]["SessionID"]
                    extensions = client_hello.parsed_content["ClientHello"]["Extensions"]

                    # 客户端公钥获取与服务端公钥、私钥生成
                    find_client_public_key = False
                    for e in extensions:
                        if e["ExtensionName"] == ExtensionName.KeyShare.value:
                            key_share = Protocol(client_hello_public_keyshare_struct, e["ExtensionContent"])
                            if key_share:
                                for k in key_share.parsed_content["KeyShare"]["group"]:
                                    if k["Type"] == b"\x00\x1d":  # x25519协议,当前仅支持x25519协议
                                        client_public_key = k["Content"]  # 客户端发送的公钥
                                        find_client_public_key = True
                                        break
                            break
                    if not find_client_public_key:  # 可完善，没有分类描述获取public_key失败的原因，一般是不会有问题的
                        LOG.log(
                            f'{addr}:{port}不能解析publick_key,没有发送支持x25519协议的keyshare')
                        return

                    private_key = x25519.X25519PrivateKey.generate()  # 随机生成服务端私钥
                    server_public_key = private_key.public_key()  # 从服务端私钥获取服务端公钥
                    client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_key)  # 生成客户端公钥对象
                    shared_secret = private_key.exchange(client_public_key)  # 生成shared_key 也就是 shared_secret

                    # 将server_hello装入tls
                    server_hello = copy.deepcopy(server_hello_struct_with_handshake)  # server_hello的结构
                    server_hello["ServerHelloHandShake"]["ServerHello"]["Extension"]["KeyShare"]["PublicKey"] = (32,
                                                                                                                 server_public_key.public_bytes(
                                                                                                                     encoding=serialization.Encoding.Raw,
                                                                                                                     format=serialization.PublicFormat.Raw))
                    server_hello_random = bytes.fromhex(
                        f'{hex(int(datetime.datetime.now().timestamp() * 10 ** 6))[-8:]}') + bytes.fromhex(
                        f'{hex(random.randint(0, 16 ** 56))[2:]:0>56}')
                    server_hello["ServerHelloHandShake"]["ServerHello"]["Random"] = (32, server_hello_random)
                    server_hello["ServerHelloHandShake"]["ServerHello"]["SessionID"] = (None, client_session_id)
                    server_hello_handshake_data = bytes(Protocol(server_hello))
                    hand_shake_hash.update(server_hello_handshake_data)  # 更新握手数据的hash

                    server_hello_tls = copy.deepcopy(server_TLS_struct)
                    server_hello_tls["TLS"]["TLSContent"] = (None, server_hello_handshake_data)  # 将server hello装入
                    writer.write(  # 发送 server_hello和change_cipher_spec
                        bytes(Protocol(server_hello_tls)) + bytes(Protocol(server_change_cipher_spec_struct_with_tls)))

                    # 计算handshake key
                    early_secret = hkdf_extract(b"\x00" * 32, zero_key, hashlib.sha256)
                    derived_secret = hkdf_expand_label(early_secret, b"derived", empty_hash)
                    handshake_secret = hkdf_extract(derived_secret, shared_secret, hashlib.sha256)
                    client_handshake_traffic_secret = hkdf_expand_label(handshake_secret, b"c hs traffic",
                                                                        hand_shake_hash.digest(),
                                                                        32)
                    server_handshake_traffic_secret = hkdf_expand_label(handshake_secret, b"s hs traffic",
                                                                        hand_shake_hash.digest(),
                                                                        32)
                    client_handshake_key = hkdf_expand_label(client_handshake_traffic_secret, b"key", b"", 16)
                    server_handshake_key = hkdf_expand_label(server_handshake_traffic_secret, b"key", b"", 16)
                    client_handshake_iv = hkdf_expand_label(client_handshake_traffic_secret, b"iv", b"", 12)
                    server_handshake_iv = hkdf_expand_label(server_handshake_traffic_secret, b"iv", b"", 12)

                    # 生成encrypt_extension和certificate，此阶段之后数据加密
                    encrypt_extension_data = bytes(Protocol(encrypted_extensions_struct))
                    hand_shake_hash.update(encrypt_extension_data)  # 跟新握手数据的hash
                    server_certificate_data = bytes(Protocol(server_certificate_handshake_struct))
                    hand_shake_hash.update(server_certificate_data)  # 跟新握手数据的hash
                    # 加密发送encrypt_extension和certificate
                    encrypt_data = encrypt_extension_data + server_certificate_data + b"\x16"  # 要加密的信息
                    encrypt_data, authtag = aes_gcm_encrypt(server_handshake_key, server_handshake_iv,
                                                            b"\x17\x03\x03" + bytes.fromhex(
                                                                f"{hex(len(encrypt_data) + 16)[2:]:0>4}"),
                                                            encrypt_data,
                                                            server_handshake_record_num)

                    application_data = copy.deepcopy(tls_application_data_struct)
                    application_data["ApplicationDataStruct"]["EncrypteData"] = (None, encrypt_data + authtag)
                    writer.write(bytes(Protocol(application_data)))
                    server_handshake_record_num += 1

                    # 生成certificate verify
                    message = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + hand_shake_hash.digest()  # certificate verify中的要签名的信息
                    signature = rsa_pss_rase_sha256_sign(PRIVATE_KEY, message)  # certificate verify中的签名
                    server_certificate_verify = copy.deepcopy(server_certificate_verify_struct)
                    server_certificate_verify["ServerCertificateVerify"]["Signature"]["Signature"] = (None, signature)
                    server_certificate_verify_data = bytes(Protocol(server_certificate_verify))
                    hand_shake_hash.update(server_certificate_verify_data)

                    # 生成handshake_finished
                    finished_key = hkdf_expand_label(server_handshake_traffic_secret, b"finished", b"", 32)
                    server_handshake_finished = copy.deepcopy(server_handshake_finished_struct)
                    server_handshake_finished["ServerHandshakeFinishedStruct"]["VerifyData"] = (
                        None, hmac_sha256(finished_key, hand_shake_hash.digest()))
                    server_handshake_finished_data = bytes(Protocol(server_handshake_finished))
                    hand_shake_hash.update(server_handshake_finished_data)

                    # 加密发送certificate_verify和handshake_finished
                    encrypt_data = server_certificate_verify_data + server_handshake_finished_data + b"\x16"  # 要加密的信息
                    encrypt_data, authtag = aes_gcm_encrypt(server_handshake_key, server_handshake_iv,
                                                            b"\x17\x03\x03" + bytes.fromhex(
                                                                f"{hex(len(encrypt_data) + 16)[2:]:0>4}"),
                                                            encrypt_data,
                                                            server_handshake_record_num)

                    application_data = copy.deepcopy(tls_application_data_struct)
                    application_data["ApplicationDataStruct"]["EncrypteData"] = (None, encrypt_data + authtag)
                    writer.write(bytes(Protocol(application_data)))
                    server_handshake_record_num += 1

                    await writer.drain()  # 等候消息发送完，此时可以执行其它任务

                    # 计算application key
                    derived_secret = hkdf_expand_label(handshake_secret, b"derived", empty_hash, 32)
                    master_secret = hkdf_extract(derived_secret, zero_key, hashlib.sha256)
                    client_application_traffic_secret = hkdf_expand_label(master_secret, b"c ap traffic",
                                                                          hand_shake_hash.digest(), 32)
                    server_application_traffic_secret = hkdf_expand_label(master_secret, b"s ap traffic",
                                                                          hand_shake_hash.digest(), 32)
                    client_application_key = hkdf_expand_label(client_application_traffic_secret, b"key", b"", 16)
                    server_application_key = hkdf_expand_label(server_application_traffic_secret, b"key", b"", 16)
                    client_application_iv = hkdf_expand_label(client_application_traffic_secret, b"iv", b"", 12)
                    server_application_iv = hkdf_expand_label(server_application_traffic_secret, b"iv", b"", 12)

                    LOG.log(f'{addr}:{port}服务器握手完成 {current_time()}')
                else:
                    LOG.log(
                        f'{addr}:{port}未知的握手协议类型: {hand_shake_type}')
                    return

            elif tls_type == TLSType.application_data.value:  # 收到客户端的加密数据
                # encrypted_data, authtag,addition_data 对于不同阶段的加密内容来说是一样的,不重复代码
                encrypted_data, authtag = tls.parsed_content["TLS"]["TLSContent"][:-16], \
                                          tls.parsed_content["TLS"]["TLSContent"][-16:]
                addition_data = tls.parsed_content["TLS"]["TLSType"] + tls.parsed_content["TLS"]["TLSVersion"] + \
                                tls.parsed_content["TLS"]["Length"]

                if client_handshake_is_finished:  # 客户端已经发送client_handshake_finished，用application_key解密
                    decrypted_data = aes_gcm_decrypt(client_application_key, client_application_iv, addition_data,
                                                     encrypted_data, authtag, client_application_record_num)
                    client_application_record_num += 1

                    if not decrypted_data:  # 解密失败
                        LOG.log(f'{addr}:{port}application_key解密失败')
                        return

                    decrypted_data_type = decrypted_data[-1:]
                    decrypted_data = decrypted_data[:-1]  # 去除最后的表示类型的字节
                    if decrypted_data_type == b"\x17":  # 收到http请求

                        LOG.log(f'{addr}:{port} 发出http请求 {current_time()}')

                        # 发送newssionticket
                        server_newsessiontickets = b""  # 发送多个newsessionticket
                        for i in range(2):
                            server_newsessionticket = copy.deepcopy(server_newSession_ticket_with_handshake_struct)
                            server_newsessionticket["NewSessionTicketHandShake"]["NewSessionTicket"]["TicketNonce"][
                                "NonceValue"] = (None, bytes.fromhex(f"{hex(random.randint(0, 2 ** 32))[2:]:0>8}"))
                            server_newsessionticket["NewSessionTicketHandShake"]["NewSessionTicket"]["SessionTicket"][
                                "SessionTicket"] = (None, b"12345678")
                            server_newsessiontickets += bytes(Protocol(server_newsessionticket))

                        encrypt_data = server_newsessiontickets + b"\x16"  # 要加密的信息
                        encrypt_data, authtag = aes_gcm_encrypt(server_application_key, server_application_iv,
                                                                b"\x17\x03\x03" + bytes.fromhex(
                                                                    f"{hex(len(encrypt_data) + 16)[2:]:0>4}"),
                                                                encrypt_data, server_application_record_num)

                        application_data = copy.deepcopy(tls_application_data_struct)
                        application_data["ApplicationDataStruct"]["EncrypteData"] = (None, encrypt_data + authtag)
                        writer.write(bytes(Protocol(application_data)))
                        server_application_record_num += 1

                        response = await  _http_request_hanlder(decrypted_data)  # 得到对应请求的回应
                        encrypt_data = response + b"\x17"  # 要加密的信息
                        encrypt_data, authtag = aes_gcm_encrypt(server_application_key, server_application_iv,
                                                                b"\x17\x03\x03" + bytes.fromhex(
                                                                    f"{hex(len(encrypt_data) + 16)[2:]:0>4}"),
                                                                encrypt_data, server_application_record_num)

                        application_data = copy.deepcopy(tls_application_data_struct)
                        application_data["ApplicationDataStruct"]["EncrypteData"] = (None, encrypt_data + authtag)
                        application_data = bytes(Protocol(application_data))  # 要发送的内容字节
                        server_application_record_num += 1

                        l = len(application_data)  # 要发送的内容长度
                        if l < SEND_BYTES_NUM:
                            writer.write(application_data)  # 一次性发送
                            await writer.drain()
                        else:  # 每次发送一部分,来均摊流量
                            s = 0
                            end = SEND_BYTES_NUM
                            while end < l:  # 每次发送的字节数
                                writer.write(application_data[s, end])
                                s += SEND_BYTES_NUM
                                end += SEND_BYTES_NUM
                                await writer.drain()
                                _update_client_access_info(addr, socket)  # 更新互动时间，避免被当成僵尸任务

                        LOG.log(f'{addr}:{port} 收到回复 {current_time()}')
                    elif decrypted_data_type == b"\x15":  # 加密的是alert
                        alert = Protocol(alert_struct, decrypted_data, strict=True)  # 解析alert协议
                        if alert:  # 解析成功
                            LOG.log(
                                f'{addr}:{port}客户端发出警告，level: {alert.parsed_content["Alert"]["Level"]},description: {alert.parsed_content["Alert"]["Description"]}')
                            return
                        else:
                            LOG.log(
                                f'{addr}:{port}客户端发出的警告信息解析失败')
                            return
                    else:
                        LOG.log(
                            f'{addr}:{port}客户端发送的加密类型为{decrypted_data_type}不能解析')
                        return
                else:  # 用handshake_key解密
                    decrypted_data = aes_gcm_decrypt(client_handshake_key, client_handshake_iv, addition_data,
                                                     encrypted_data, authtag, client_handshake_record_num)
                    client_handshake_record_num += 1

                    if not decrypted_data:  # 解密失败
                        LOG.log(
                            f"{addr}:{port}handshake_key解密客户端数据失败")
                        return

                    decrypted_data_type = decrypted_data[-1:]  # 待完善 不能用[-1],不知道为什么
                    decrypted_data = decrypted_data[:-1]  # 去除最后一位表示协议类型的字节
                    if decrypted_data_type == b"\x16":  # 加密的是握手协议
                        hand_shake = Protocol(hand_shake_struct, decrypted_data, strict=True)  # 解析握手协议，
                        if not hand_shake:
                            LOG.log(
                                f"{addr}:{port}客户端发送的加密数据不符合握手协议")
                            return

                        hand_shake_type = hand_shake.parsed_content["HandShake"]["HandShakeType"]
                        if hand_shake_type == HandShakeType.handshake_finished.value:  # client发送handshake_finished
                            client_handshake_finished = Protocol(client_handshake_finished_struct,
                                                                 decrypted_data,
                                                                 strict=True)  # 解析client_handshake_finished协议
                            finished_key = hkdf_expand_label(client_handshake_traffic_secret, b"finished", b"", 32)
                            verify_data = hmac_sha256(finished_key, hand_shake_hash.digest())
                            if verify_data == \
                                    client_handshake_finished.parsed_content["ClientHandshakeFinishedStruct"][
                                        "VerifyData"]:
                                client_handshake_is_finished = True
                                LOG.log(f'{addr}:{port}客户端握手完成 {current_time()}')
                            else:
                                LOG.log(
                                    f'{addr}:{port}客户端发送的加密数据verify失败')
                                return
                        else:
                            LOG.log(
                                f'{addr}:{port}handshake_key解密成功,客户端发送的握手协议类型为 {hand_shake_type} 不能解析')
                            return
                    elif decrypted_data_type == b"\x15":  # 加密的是alert
                        alert = Protocol(alert_struct, decrypted_data, strict=True)  # 解析alert协议
                        if alert:  # 解析成功
                            LOG.log(
                                f'{addr}:{port}客户端发出警告，level: {alert.parsed_content["Alert"]["Level"]},description: {alert.parsed_content["Alert"]["Description"]}')
                            return
                        else:
                            LOG.log(
                                f'{addr}:{port}客户端发出的警告信息解析失败')
                            return
                    else:
                        LOG.log(
                            f'{addr}:{port}客户端发送的加密类型为{decrypted_data_type}不能解析')
                        return

            elif tls_type == TLSType.change_cipher_spec.value:  # 发送change_cipher_spec
                pass  # tls1.3 不需要管

            elif tls_type == TLSType.alert.value:
                alert = Protocol(alert_struct, tls.parsed_content["TLS"]["TLSContent"], strict=True)  # 解析alert协议
                if alert:  # 解析成功
                    LOG.log(
                        f'{addr}:{port}客户端发出警告，level: {alert.parsed_content["Alert"]["Level"]},description: {alert.parsed_content["Alert"]["Description"]}')
                    return
                else:
                    LOG.log(
                        f'{addr}:{port}客户端发出的警告信息解析失败')
                    return

            else:  # 未知的tls协议
                LOG.log(f'{addr}:{port}客户端发送未知的tls协议,类型为 {tls_type}')
                return
    except ConnectionAbortedError:
        LOG.log(f'{addr}:{port}主动断开链接')
    except Exception as e:
        LOG.log(
            f"{addr}:{port}处理https请求(https_request_handler)出错，错误信息:{e}\n详细信息:\n{traceback.format_exc()}")
    finally:
        try:  # 避免task错误
            socket.shutdown(2)
            socket.close()
        finally:
            return


async def _http_server(reader, writer):
    """
    处理http请求
    :param reader:
    :param writer:
    :return:
    """
    pass


async def _create_Server(protocol: str, port: int):
    if protocol == "https":
        """异步https服务器"""

        server = await asyncio.start_server(_https_server, "", port, family=socket.AF_INET,
                                            backlog=MAX_LISTENER_NUM)
    elif protocol == "http":
        """异步http服务器"""

        server = await asyncio.start_server(_http_server, "", port, family=socket.AF_INET,
                                            backlog=MAX_LISTENER_NUM)

    async with server:
        await server.serve_forever()


@LOG(f"开启服务器 {current_time()}")
def start_server(protocol: str = "https", port: int = None):
    """
    启动https或者http服务器
    :param protocol: 协议类型 https或者http
    :param port: 端口号
    :return:
    """
    if protocol not in ("http", "https"):
        raise ValueError(f' 协议类型错误，{protocol} 应该改为 "http" 或 "https"')

    if port is None:
        port = {"https": 443, "http": 80}[protocol]
    else:
        port = int(port)
        if port > 655353 or port < 0:  # 端口号不符合标准
            raise ValueError(f"{port} 是不合法的端口")

    asyncio.run(_create_Server(protocol, port))
    return
