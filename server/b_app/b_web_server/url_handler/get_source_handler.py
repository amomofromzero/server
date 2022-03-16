import os
from enum import Enum

import b_read_from_file

read_from_file = b_read_from_file.read_from_file


class Status(Enum):
    """存储各个状态"""
    s_200 = b"HTTP/1.1 200 OK\r\n"


html_header = "content-type: text/html;charset=utf-8\r\ncontent-Length: {}\r\n\r\n"

file_header = 'content-type: {}\r\ncontent-Length: {}\r\n\r\n'
conten_typet_map = {"png": "image/png"}  # 根据文件扩展名，映射为content-type


def main(request):
    file_path = "./b_app/b_web_server/web_data/web_source_code" + request["url"]
    if os.path.exists(file_path) and os.path.isfile(file_path):
        file = read_from_file(file_path)
        return Status.s_200.value + file_header.format(conten_typet_map[os.path.splitext(file_path)[1][1:]],
                                                       len(file)).encode("utf-8") + file
    else:
        file = read_from_file("./b_app/b_web_server/web_data/web_source_code/index.html")
        return Status.s_200.value + html_header.format(len(file)).encode("utf-8") + file
