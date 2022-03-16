import time
import traceback

import log

_LOG = log.LOG

FILE_CACHE = {}  # 缓存的文件
_INTERVAL_TIME = 5  # 文件访问时间小于5秒，频率增加，否则下降

"""
读取文件,常用文件会缓存下来,避免每次读取
最后修改时间:2022 03 13
"""


class _File_INFO():
    """记录缓存文件使用的情况，释放不常使用的文件"""

    def __init__(self, filename: str, content: bytes):
        self.frequency = 0
        self.last_use_time = time.time()
        self.filename = filename
        self.content = content

        _LOG.log(f"新增文件缓存 {self.filename},当前所有缓存文件 {FILE_CACHE.keys()}")

    def update(self):
        interval = time.time() - self.last_use_time  # 两次访问的间隔时间
        self.last_use_time = time.time()

        if interval < _INTERVAL_TIME:  # 间隔时间较短，频率越低
            self.frequency += 1
        else:
            self.frequency -= interval / _INTERVAL_TIME  # 间隔时间越长，频率越低

        if self.frequency < 0:  # 访问频率较低，删除缓存

            _LOG.log(f"删除文件缓存 {self.filename},当前所有缓存文件 {FILE_CACHE.keys()}")

            del FILE_CACHE[self.filename]


@_LOG("读取文件")
def read_from_file(filename: str):
    """
    从文件获取内容，如果在缓存中，直接返回，否则直接加入缓存
    :param filename:
    :return:返回文件内容，出错时，返回None
    """
    try:
        if filename not in FILE_CACHE:  # 缓存中没有该文件,从文件中读取
            with open(filename, "rb") as f:
                FILE_CACHE[filename] = _File_INFO(filename, f.read())
        return FILE_CACHE[filename].content
    except Exception as e:
        _LOG.log(f"读取文件出错(read_from_file),错误信息 {e}\n详细信息:\n{traceback.format_exc()}", tag="error")
        return None
