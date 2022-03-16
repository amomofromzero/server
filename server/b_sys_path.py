import os
import sys

"""
将当前路径下面的每个文件夹添加到sys.path,方便调用
"""


def _append_all_path(path):
    """
    将当前路径下面的每个文件夹添加到sys.path,方便调用
    """
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    for root, dirctory, file in os.walk(path):
        for d in dirctory:
            sys.path.append(os.path.join(root, d))


_append_all_path("./")
