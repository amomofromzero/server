import datetime
import os.path
import re
from threading import Lock
import traceback
from functools import wraps
from atexit import register

"""
测试相关
最后修改时间 2022 03 13
"""


class Log:
    """
    输出或记录日志信息
    其中 是否输出到日志文件（log_to_file），是否打印到屏幕（log_to_screen ）可以从类、实例以及每次调用(__call__)三个层面来进行控制
    """
    log_to_file = True
    log_to_screen = True
    max_size = 1000  # 默认内存临时储存log的最大字数，超过以后，会写入文件之中
    indent = "  "  # 控制前缀
    indent_length = len(indent)

    def __init__(self, log_file_name: str = None, log_to_file: bool = None, log_to_screen: bool = None,
                 indent: str = None):
        """
        :param log_file_name: 日志保存的路径
        :param log_to_file: 是否打印到文件
        :param log_to_screen: 是否打印到屏幕
        :param indent: 控制每次缩进空格数
        """
        # 日志保存位置
        try:
            _dn, _fn = os.path.split(log_file_name)
            if _dn:
                try:  # 尝试创建文件夹
                    os.makedirs(_dn)
                except FileExistsError:  # 已经存在该文件夹
                    pass  # 正常执行下面代码

            with open(log_file_name, "a", encoding="utf-8") as f:  # 尝试创建文件
                f.write(f"日志时间:{datetime.datetime.now().strftime('%Y %m %d %H %M %S')}\n")
                f.write("<style>*{white-space:pre-wrap;}</style>")  # css设置属性，保证空格不合并，换行符子自动识别
                self.log_file_name = log_file_name

        except Exception:  # 没能创建log文件
            self.log_file_name = f"./log-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.html"  # 默认log文件名
            with open(self.log_file_name, "a", encoding="utf-8") as f:
                f.write(f"日志时间:{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}\n")
                f.write("<style>*{white-space:pre-wrap;}</style>")  # css设置属性，保证空格不合并，换行符子自动识别

        self._log = ""  # 内存中存储的日志信息,有最大字数的限制，全部日志存储在文件中

        if log_to_file is not None:
            self.log_to_file = log_to_file
        if log_to_screen is not None:
            self.log_to_screen = log_to_screen
        if indent is not None:
            self.indent = indent  # 最小是1，避免出错
            self.indent_length = len(indent)

        self._log_indent = ""  # log输出的时候的总的缩进,能显示出层次结构
        self._write_file_lock = Lock()  # 读写日志文件的lock
        self._log_lock = Lock()  # 打印时候的lock
        self._dec_lock = Lock()  # 装饰器用的lock
        self._end_with_enter = False  # 上次是否以回车结束

        register(self.__flush)  # 注册析构函数，类删除时候调用flush保存日志

    def __call__(self, func_promption: str = None, tag: str = None, log_to_file: bool = None,
                 log_to_screen: bool = None):

        log_to_file = self.log_to_file if log_to_file is None else log_to_file
        log_to_screen = self.log_to_screen if log_to_screen is None else log_to_screen

        def dec(func):
            @wraps(func)
            def w1(*args, **argv):
                self._dec_lock.acquire()  # 申请线程锁
                func_name = func.__name__ if func_promption is None else f"{func_promption}({func.__name__})"

                if tag is not None:
                    self.log(f"<{tag}>")

                self.log(func_name, log_to_file=log_to_file, log_to_screen=log_to_screen)  # 输出函数名称

                self._log_indent += self.indent
                self._dec_lock.release()
                try:
                    return func(*args, **argv)
                except Exception as e:
                    self._dec_lock.acquire()
                    try:  # 打印错误过程中可能出错,__init__' method of object's base class (MainWindow) not called
                        self.log(
                            f'{func_name} 失败,错误信息: {e}, 参数:[args:{args}, argv:{argv}]\n详细信息:\n{traceback.format_exc()}\n',
                            log_to_file=log_to_file, log_to_screen=log_to_screen, tag="error")
                    except Exception as e:
                        self.log(f'{func_name} 失败,错误信息: {e}\n详细信息:\n{traceback.format_exc()}\n',
                                 log_to_file=log_to_file, log_to_screen=log_to_screen, tag="error")
                    self._dec_lock.release()
                finally:
                    self._dec_lock.acquire()
                    self._log_indent = self._log_indent[:-self.indent_length]
                    if tag is not None:
                        self.log(f"</{str(tag)}>")
                    self._dec_lock.release()

            return w1

        return dec

    def log(self, *args, log_to_file: bool = None, log_to_screen: bool = None, tag: str = "", end: str = "\n",
            sep: str = " ", **kwargs) -> str:
        """
        输出或记录日志信息
        :param args: 要打印的信息
        :param log_to_file: 是否保存到日志文件中
        :param log_to_screen: 是否在屏幕上输出
        :param tag: 包裹内容的标签，如html
        :param end: 结尾符号，类似print里的end
        :param sep: 参数之间的分割符号，类似print里的sep
        :param kwargs: 其它需要传递给print的参数
        :return: 输出的文字
        """
        try:
            self._log_lock.acquire()  # 线程锁，避免同时输入文字串出错

            log_to_screen = self.log_to_screen if log_to_screen is None else log_to_screen
            log_to_file = self.log_to_file if log_to_file is None else log_to_file
            args = [str(s) for s in args]  # 全部转换为变为字符串格式

            new_log = f"<{tag}>" if tag else ""
            if self._end_with_enter:
                new_log += self._log_indent

            for s in args[0:-1]:  # 最后一个字符不需要加sep
                new_log += (s + sep)
            new_log = (new_log + args[-1] + end)  # 加上最后一个字符，换行替换为换行+indent
            if new_log.endswith("\n"):
                new_log = new_log.replace("\n", "\n" + self._log_indent)
                new_log = new_log[:len(new_log) - len(self._log_indent)]  # 最后的\n不需要加 self._log_indent
                self._end_with_enter = True
            else:
                new_log = new_log.replace("\n", "<br>" + self._log_indent)
                self._end_with_enter = False
            if tag:
                new_log += f"</{tag}>"

            if log_to_screen:  # 打印到屏幕
                print(new_log, end="", sep="", **kwargs)

            if log_to_file:  # 写入日志
                self._log += new_log
                if len(self._log) > self.max_size:
                    self.__flush()

        except Exception as e:
            print(f"打印日志出错({self.log}),日志路径: {self.log_file_name},错误信息: {e}\n详细信息:\n{traceback.format_exc()}")
        finally:
            self._log_lock.release()

    def __flush(self):
        self._write_file_lock.acquire()
        try:
            with open(self.log_file_name, "a+", encoding="utf-8") as f:
                f.write(self._log)
                self._log = ""
        except PermissionError:  # 文件被占用
            while True:  # 找到一个合适的文件来记录
                n, suffix = os.path.splitext(self.log_file_name)
                match = re.match(r"(\D*)(\d*)(\D*)", n)
                if match:
                    s1, n, s2 = match.groups()
                    fn = f"{s1}{int(n) + 1}{s2}{suffix}"
                else:
                    fn = f"{n}1{suffix}"
                if not os.path.exists(fn):
                    break
            with open(fn, "a+", encoding="utf-8") as f:
                f.write(self.__read_log() + self._log)
                self._log = ""
                self.log_file_name = fn
        except Exception as e:
            print(f"保存日志出错，({self.__flush}),日志路径: {self.log_file_name},错误信息: {e}\n详细信息:\n{traceback.format_exc()}")
        finally:
            self._write_file_lock.release()

    def __read_log(self) -> str:
        """
        读取已经记录的日志信息，并返回日志信息
        :return: 全部的日志信息
        """
        try:
            if os.path.exists(self.log_file_name):
                with open(self.log_file_name, "r", encoding="utf-8") as f:
                    return f.read() + self._log
            else:
                return self._log
        except Exception as e:
            print(f"读取日志出错，({self.__read_log}),日志路径: {self.log_file_name},错误信息: {e}\n详细信息:\n{traceback.format_exc()}")
