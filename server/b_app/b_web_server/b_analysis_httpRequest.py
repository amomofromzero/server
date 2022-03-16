import re
import traceback
from urllib.parse import unquote
import log

_LOG = log.LOG

"""
解析http请求
最后修改 2022 03 13
"""


def analysis_httpRequest(requestText: bytes):
    """
    解析http请求
    :param requestText: http请求字节串
    :return: 解析后的请求 示例:{"method": "", "url": "", "params":{}, "headers": {}, "protocal": "", "data": b""}
    """

    try:
        _rt = requestText.split(b"\r\n")  # 根据\r\n分割
        request_ = {"method": "", "url": "", "params": {}, "protocal": "", "headers": {},
                    "data": b""}  # 初始化请求,为防止意外情况，data返回bytes对象
        text = unquote(_rt[0].decode("utf-8"))  # http请求状态和url的信息

        if not text:  # 返回空数据，关闭连结
            return None

        request_["method"], request_["url"], request_["protocal"] = text.split(" ")

        _params = re.findall("([^\?&]+)=([^\?&]+)", request_["url"])  # 解析get方法的参数
        for k, v in _params:
            request_["params"][k] = v

        del _rt[0]  # 删除第一行,也就是删除http请求状态和url的信息，准备解析下面的部分

        _read_data = False  # 正在读取头，没有读到data部分
        for r in _rt:  # 解析headers
            if r:
                if _read_data:  # 读取数据
                    request_["data"] += r
                else:  # 读取头
                    r = r.decode("utf-8")
                    k, v = r.split(":", 1)  # 将head转换为字典
                    request_["headers"][k] = v
            else:  # 因为头和数据之间有两个\r\n分割，因此遇到空字符证明读取到数据部分了
                _read_data = True  # 读取数据部分
        return request_
    except Exception as e:
        _LOG.log(f"解析http出错，错误信息:{e}  http请求为:\n {requestText}\n详细信息:\n{traceback.format_exc()}", tag="error")
        return None
