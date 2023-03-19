import gzip

from http import HTTPStatus, cookies
from functools import lru_cache

ERROR_CODE = {
    str(value): ('HTTP/1.1 {0} {1}\r\n'.format(value, name.replace('_', ' '))).encode("utf-8")
    for name, value in HTTPStatus.__members__.items() if name.isupper()
}


class Session:
    def __init__(self, session_id, user_name, access_ability) -> None:
        self.session_id = session_id
        self.user_name = user_name
        self.access_ability = access_ability


class ResponseHead(dict):
    def __str__(self):
        temp = ''
        for key, value in self.items():
            temp += "{}: {}\r\n".format(key, value)
        return temp

    def __repr__(self):
        return self.__str__()

    def __bytes__(self):
        return self.__str__().encode('utf-8')


class Cookies(cookies.SimpleCookie):
    def __str__(self):
        return self.output(header='').strip()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self):
        return self.__str__().encode('utf-8')


# 用于缓存文件, 以减少磁盘IO, 但是会占用更多内存
# noinspection PyTypeChecker
@lru_cache(maxsize=256)
def read_file(filename: str, mode='rb', enable_gzip=False):
    with open(filename, mode) as f:
        if enable_gzip and mode == 'rb':
            return gzip.compress(f.read())
        else:
            return f.read()


if __name__ == '__main__':
    print('二寸'.encode('utf-8'))
    "\xe4\xba\x8c\xe5\xaf\xb8"
    print("\udce4\udcba\udc8c\udce5\udcaf\udcb8.jpg")
