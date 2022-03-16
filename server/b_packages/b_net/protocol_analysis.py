class Protocol:
    """
    一种通用的网络协议解析方法,比如tls,一般格式为（内容长度(固定字节数)+内容）
    修改日期 20220211
    """

    def __init__(self, struct: dict, content: bytes = None, strict=False):
        if content:  # 输入内容，对内容进行解析
            # 分别返回解析的内容以及内容对应的属性
            self.parsed_content, self._parsed_content = self._parse(struct, content, strict)
        else:  # 没有内容，根据struct生成字节串
            self.generated_content = self.generate(struct)
            self.parsed_content = None  # 不能少，用于判断是解析还是生成字节串
        self.__prefix = ""  # 用于repr格式化显示

    def __bool__(self):
        return bool(self.parsed_content)

    @classmethod
    def generate(cls, struct):
        """
        根据struct,生成字节串
        :param struct: 输入的字典
        :return: 输出字节串
        """
        generated_content = b""  # 最后生成的字节串
        length_num = None  # 根据内容的大小，生成内容的长度，用lengthNum个字节表示。None表示不需要计算长度
        for k, v in struct.items():
            if isinstance(v, tuple):
                num, content = v  # 对应的字节数和实际内容
                if content is None:
                    if not isinstance(num, int):
                        raise TypeError(f"类型错误，{k}对应的元组的第一位，必须是一个整数值，来限定字节数")
                    length_num = num  # 下面内容的长度未知，之后再添加,先记下位置和字节数
                elif isinstance(content, bytes):  # content是bytes类型，没有问题，对num进行验证
                    if num is not None:
                        if isinstance(num, int):
                            if len(content) != num:
                                # num不是None,证明内容具有固定长度,因此对内容长度进行检验
                                raise ValueError(
                                    f"值错误，{k} 对应的值(元组第二位)的字节数应该是{num},实际字节数是{len(content)}")
                        else:  # num不是None,也不是int类型，有问题
                            raise TypeError(f"类型错误，{k} 需要限定字节数,必须是一个整数值")

                    if length_num:  # 需要补上本内容的长度，用lengthNum个字节数表示
                        if len(content) > 256 ** length_num - 1:  # 内容长度超出lengthNum个字节数表示范围
                            raise ValueError(
                                f"内容超出限制，{k} 内容(元组第二位)最大允许长度是{256 ** length_num - 1},实际内容长度是{len(content)}")
                        else:
                            generated_content += bytes.fromhex(
                                hex(len(content))[2:].zfill(length_num * 2))  # 先加上本次内容的长度
                        length_num = None  # 这个字节的内容已经确定了，lengthNum肯定是None
                    generated_content += content  # 加上本次内容
                else:  # 必须是字节类型或者None
                    raise TypeError(f"类型错误，{k} 对应的值(元组第二位)应该是内容应该是bytes类型或者是None,实际类型是{type(content)}")
            elif isinstance(v, dict):  # 对应的值是字典
                content = cls.generate(v)
                if length_num:  # 需要填充之前的长度段
                    if len(content) > 256 ** length_num - 1:  # 内容长度超出lengthNum个字节数表示范围
                        raise ValueError(f"内容超出限制，{k} 内容最大长度是{256 ** length_num - 1},实际内容长度是{len(content)}")
                    else:
                        generated_content += bytes.fromhex(hex(len(content))[2:].zfill(num * 2))  # 先加上本次内容的长度
                    length_num = None  # 这个字节的内容已经确定了，lengthNum肯定是None
                generated_content += content  # 加上本次内容
            else:
                raise TypeError(f"类型错误，{k} 对应的应该是数组或者字典,输入的类型是{type(v)}")
        return generated_content

    @classmethod
    def _parse(cls, struct, content, strict=False, lastone=True):
        """
        将字节串(content)解析为具有一定结构(struct)的字典,建议使用match
        :param struct:字典，表示协议的结构
        :param content: 字节串内容
        :param strict: 严格模式下，需要根据参考值对内容的值进行校验
        :param lastone: 最上层，只返回需要的内容,不是最上层，要返回更多参数供上层使用
        :return:  返回content解析后的字典结构,以及带有详细内容的字典结构
        """
        try:
            if isinstance(content, bytes):
                parsed_content = {}  # 最后返回的content解析后的字典结构
                _parsed_content = {}  # 具有详细的属性，但使用不方便，主要用于显示
                _length = hex(len(content))[2:]  # 用十六进制表示内容的长度
                if len(_length) % 2 != 0:  # 字节串长度一定是8位的整除，一定是有偶数个十六进制值
                    _length = "0" + _length  # 补0，形成正确的16进制
                _length = bytes.fromhex(_length)  # 16进制字节串

                for k, v in struct.items():
                    if isinstance(v, tuple):
                        _num, _content_reference = v  # 所占的位数和参考值，如果strict为True,会根据参考值对内容进行判断
                        if _num is None:  # 证明这个长度不是固定的，而是由之前的值指定的
                            _length = int.from_bytes(_length, "big")  # length是上个字节串的内容，表示这次的内容长度
                            parsed_content[k] = content[:_length]
                            _parsed_content[k] = (content[:_length], _length)
                            content = content[_length:]
                        elif isinstance(_num, int):
                            _length = _temp_content = content[:_num]  # content可能是下一个片段的长度,保存到_length

                            if strict and _content_reference is not None:  # 严格模式下且有参考值的时候，需要判断内容是否正确
                                if isinstance(_content_reference, list):  # 参考内容是列表，对应的值应该是其中一个
                                    if _temp_content not in _content_reference:
                                        raise ValueError(
                                            f"内容错误,{k} 内容应该是 {_content_reference} 中的一个,实际内容是 {_temp_content}")
                                elif isinstance(_content_reference, bytes):  # 参考内容不是列表而是单一的字节串
                                    if _temp_content != _content_reference:
                                        raise ValueError(f"内容错误,{k} 内容应该是 {_content_reference},实际内容是 {_temp_content}")
                                else:
                                    raise TypeError(f"结构错误,{k} 的参考值类型应该是列表、字节串，实际类型是 {type(_content_reference)}")
                            parsed_content[k] = _temp_content  # 记录内容长度和内容
                            _parsed_content[k] = (_temp_content, _num)  # 记录内容长度和内容
                            content = content[_num:]
                        else:
                            raise TypeError(f"结构错误,{k} 的长度限定值,必须是一个整数值或者是None,实际是{type(_num)}")

                    elif isinstance(v, dict):  # 下一级协议或者之前长度值所包含的内容

                        _length = int.from_bytes(_length, "big")  # length是之前保存的本片段长度，转化成整数
                        _pc, __pc, content = cls._parse(v, content[:_length], lastone=False)
                        parsed_content[k] = _pc
                        _parsed_content[k] = (__pc, _length)

                    elif isinstance(v, list):  # 不定长元素，一定在最末尾
                        list_parsed_content = []
                        _list_parsed_content = {}
                        _ele_num = 0  # 表示解析出的各个元素，从0开始计数
                        _clength = _length = len(content)
                        if len(v) != 1 or not isinstance(v[0], dict):
                            raise TypeError(f"结构错误,{k} 参考值list应该只有一个元素，且元素类型是字典")
                        while True:
                            _pc, __pc, content = cls._parse(v[0], content, lastone=False)
                            ll = len(content)
                            list_parsed_content.append((_pc))
                            _list_parsed_content[str(_ele_num)] = (__pc, _length - ll)
                            _length = ll
                            _ele_num += 1
                            if not content:
                                break
                        parsed_content[k] = list_parsed_content
                        _parsed_content[k] = (_list_parsed_content, _clength)
                    else:
                        raise TypeError(f"结构错误,{k} 参考值的类型应该是dict、tuple、list中的一个,实际内容是 {type(v)}")
                if lastone:
                    return (parsed_content, _parsed_content)
                else:
                    return (parsed_content, _parsed_content, content)
            else:
                raise TypeError(f"content 对应的值应该是bytes类型,输入的类型是{type(content)}")
        except Exception:
            return (None, None)

    @classmethod
    def match(cls, struct, content, strict=False):
        """
        查看字节串(content)是否符合struct的结构
        :param struct: 字典，表示协议的结构
        :param content: 字节串内容
        :param strict: 严格模式下，需要根据参考值对内容的值进行校验
        :return:  如果匹配返回字典，如果匹配失败，返回False
        """
        try:
            parsed_content = cls._parse(struct, content, strict)[0]
            return parsed_content
        except Exception:
            return False

    def _to_string(self, _parsed_content):
        repr_str = ""
        self.__prefix += "  "
        for k, v in _parsed_content.items():
            repr_str += f"\n{self.__prefix}{k}:"
            if isinstance(v[0], dict):
                repr_str += f"({v[1]}) {self._to_string(v[0])}"
            else:
                repr_str += f"({v[1]}) {v[0]}"
        self.__prefix = self.__prefix[2:]
        return repr_str

    def __repr__(self):
        return self._to_string(self._parsed_content)

    def __bytes__(self):
        return self.generated_content
