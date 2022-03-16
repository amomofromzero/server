import b_sys_path  # 将当前目录里的所有路径加入path，方便调用包，而不需要各种import
import sys

b_sys_path.__name__  # 没用，只是为了ctrl+alt+o清除不需要的库的时候，不被清除
from b_web_server import b_web_server

"""
服务器运行主程序
最后修改 2022 03 13
"""
if __name__ == "__main__":
    if len(sys.argv) == 1:  # 没有参数
        b_web_server.start_server()  # 开启http服务器
    if len(sys.argv) == 2:
        b_web_server.start_server(sys.argv[1])
    else:
        b_web_server.start_server(sys.argv[1], sys.argv[2])
