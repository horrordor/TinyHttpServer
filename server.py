# -*- coding=utf-8 -*-
import os
import re
import sys
import atexit
import getopt
import asyncio
import logging
import secrets
import traceback
import mimetypes
import email.parser
import urllib.parse

from utils import *  # 导入工具库


# 全局变量
DEBUG = False
ROOT_DIR = 'root'
LOGGER = logging.getLogger('server')
SESSIONS = dict()


class HttpRequest(object):
    """请求处理类"""
    # 常用路径
    NotFoundHtml = ROOT_DIR + '/404.html'
    LoginHtml = ROOT_DIR + '/login.html'

    def __init__(self):
        self.url = None
        self.head = dict()
        self.method = None
        self.session = None
        self.protocol = None
        self.request_data = None
        self.response_line = None
        self.response_head = ResponseHead()
        self.response_body = bytes()

    async def __call__(self, reader, writer):
        # 处理请求
        try:
            deadline = asyncio.get_running_loop().time() + 15
            async with asyncio.timeout_at(deadline):
                # 解析请求行
                request_line = await reader.readline()
                if not request_line:
                    raise ConnectionAbortedError
                else:
                    self.parse_request_line(request_line.decode('utf-8'))

                # 解析请求头
                request_head = await reader.readuntil(b'\r\n\r\n')
                request_head = request_head.removesuffix(b'\r\n\r\n')
                if not request_head:
                    raise ConnectionAbortedError
                else:
                    self.parse_request_head(request_head.decode('utf-8'))

                # 解析session和请求体
                self.process_session()
                self.request_data = await reader.readexactly(int(self.head.get('Content-Length', 0)))

                # 路由请求
                self.route_requests()

                # 发送响应
                response_header, response_body = self.get_response()
                writer.write(response_header)
                writer.write(response_body)
                await writer.drain()

                # 关闭连接
                writer.close()
                await writer.wait_closed()
        except asyncio.TimeoutError:
            # 超时,记录日志
            LOGGER.error('connection timeout')
            raise ConnectionAbortedError

    def parse_request_line(self, request_line: str):
        header_list = request_line.split(' ')
        self.method = header_list[0].upper()
        self.url = urllib.parse.unquote(header_list[1])
        self.protocol = header_list[2]

    def parse_request_head(self, request_head: str):
        head_options = request_head.split('\r\n')
        for option in head_options:
            key, val = option.split(': ', 1)
            self.head[key] = val
        if 'Cookie' in self.head.keys():
            self.head['Cookie'] = Cookies(self.head['Cookie'])

    def process_session(self):
        # 创建或者加载session
        if self.head.get('Cookie', None) and 'session' in self.head['Cookie'].keys():
            self.session = SESSIONS.get(
                self.head['Cookie']['session'].value, None
            )
            if self.session is None:
                self.response_head |= {
                    'Set-Cookie': 'session=; max-age=0; HttpOnly; Path=/'
                }

    def create_session(self, user_name="guest", access_ability=False):
        self.session = Session(
            secrets.token_urlsafe(), user_name, access_ability
        )
        SESSIONS[self.session.session_id] = self.session
        self.response_head |= {
            'Set-Cookie': 'session=' + self.session.session_id + '; HttpOnly; Path=/'
        }

    def reject_directly(self, code='404'):
        self.response_line = ERROR_CODE[code]
        self.response_head |= {'Content-Type': 'text/html'}
        self.response_body = read_file(self.NotFoundHtml, enable_gzip=False) \
            .replace(b'{{code}}', code.encode('utf-8')) \
            .replace(b'{{message}}', ERROR_CODE[code].removeprefix(b'HTTP/1.1 '))

    def route_requests(self):
        # 处理不同请求方法
        match (self.method, bool(self.session) and self.session.access_ability):
            case ('POST', access_ability):
                if access_ability or self.url in ['/login', '/login/']:
                    # 合法的post视为动态请求
                    self.dynamic_request(ROOT_DIR + self.url)
                else:
                    # 拒接未登录用户
                    self.reject_directly(code='403')
            case ('GET', False):
                # 未登录用户跳转到登录页面
                if (os.path.isfile(self.LoginHtml)):
                    self.static_request(self.LoginHtml)
                else:
                    self.create_session(access_ability=True)
                    self.static_request(ROOT_DIR + self.url)
            case ('GET', True):
                if self.url.find('?') != -1:
                    # 含有参数的get视为动态请求
                    s_url, req = self.url.split('?', 1)
                    self.request_data = urllib.parse.parse_qs(req)
                    self.dynamic_request(ROOT_DIR + s_url)
                else:
                    # 不带参数的get视为静态请求
                    self.static_request(ROOT_DIR + self.url)
            case _:
                # 不处理GET和POST以外的请求
                self.reject_directly('501')

    def static_request(self, path):
        LOGGER.debug('static request' + path)
        if not os.path.isfile(path):
            # 路由修正
            if os.path.isfile(path + 'index.html'):
                self.static_request(path + 'index.html')
            elif os.path.isfile(path + '.html'):
                self.static_request(path + '.html')
            elif os.path.isfile(path + '/index.html'):
                self.static_request(path + '/index.html')
            else:
                self.reject_directly()
        else:
            # 提供静态文件
            self.response_line = ERROR_CODE['200']
            self.response_head |= {
                'Content-Type': mimetypes.guess_type(path)[0] or 'application/octet-stream',
                'Content-Encoding': 'gzip'
            }
            self.response_body = read_file(path, enable_gzip=True)

    def dynamic_request(self, path):
        path = path.removeprefix(ROOT_DIR)
        LOGGER.debug('dynamic request' + path)
        # 请求路由
        match (path, self.method):
            case ('/login' | '/login/', 'POST'):
                temp = urllib.parse.parse_qs(self.request_data.decode('utf-8'))
                user_name = temp.get('name', None)
                password = temp.get('password', None)
                if (user_name and password) and (user_name[0] == '123' and password[0] == '123'):
                    self.create_session(
                        user_name=user_name[0], access_ability=True)
                    self.response_line = ERROR_CODE['303']
                    self.response_head |= {'Location': '/'}  # 重定向到首页
                else:
                    self.response_line = ERROR_CODE['303']
                    self.response_head |= {
                        'Location': self.LoginHtml.removeprefix(ROOT_DIR),
                        'Set-Cookie': 'session=; max-age=0; HttpOnly; Path=/'
                    }  # 重定向到登录页, 并清除session
            case ('/upload' | '/upload/', 'POST'):
                data = b'Content-Type: ' + \
                    self.head['Content-Type'].encode('utf-8') + \
                    b'\r\n\r\n' + self.request_data
                msg = email.parser.BytesParser().parsebytes(data)
                file_names = re.finditer(
                    rb'filename="(.*)"', self.request_data)
                if msg.is_multipart() and file_names:
                    for part in msg.get_payload():
                        # email.parser模块解析出来的中文文件名是乱码，需要手动解码
                        if part.get_filename():
                            file_name = file_names.__next__().group(1).decode(
                                'utf-8').replace('\\', '/').split('/')[-1]
                            with open(ROOT_DIR + '/upload/' + file_name, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                    self.response_line = ERROR_CODE['200']
                    self.response_head |= {'Content-Type': 'text/html'}
                    self.response_body = b'<html><body><h1>Upload Success</h1></body></html>'
                else:
                    self.reject_directly('400')
            case _:
                self.reject_directly()

    def get_response(self):
        # 拒绝长连接
        self.response_head |= {
            'Connection': 'close',
            'Content-Length': str(len(self.response_body))
        }

        response_head = self.response_line + \
            bytes(self.response_head) + b'\r\n'
        return response_head, self.response_body


async def handle_request(reader, writer):
    """每个连接都会自动创建一个协程调用此函数，用于处理请求"""
    # noinspection PyBroadException
    try:
        await HttpRequest()(reader, writer)
    except ConnectionAbortedError:
        # 客户端强制关闭连接
        LOGGER.debug('Connection aborted')
        writer.close()
        await writer.wait_closed()
    except Exception:
        LOGGER.error(traceback.format_exc())
        writer.close()
        await writer.wait_closed()


def main(address='127.0.0.1', p=80):
    # 事件循环初始化
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if DEBUG:
        loop.set_debug(True)

    # 用协程创建服务器,并将handle_request作为默认回调函数
    server = loop.run_until_complete(
        asyncio.start_server(handle_request, address, int(p)))

    # 获取服务器地址，用于调试
    hosts = server.sockets[0].getsockname()
    print('Serving on {}. Hit CTRL_C to stop.'.format(hosts))
    LOGGER.info('Serving on.')

    # 开始监听连接
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        # 监听到键盘中断，关闭服务器（可以使用Ctrl+C关闭服务器）
        server.close()
        loop.run_until_complete(server.wait_closed())
    finally:
        print('\nServer shutting down', flush=True)
        LOGGER.info('Server shutting down')


@atexit.register
def cleaner():
    # 服务器异常退出时，记录异常信息
    info = traceback.format_exc()
    if info != 'NoneType: None\n':
        print("server crash, please check the log", flush=True)
        LOGGER.critical(info)


if __name__ == '__main__':
    # 默认参数
    ip = '127.0.0.1'
    port = 80

    # 读取命令行参数
    try:
        options, args = getopt.getopt(
            sys.argv[1:], 'udi:p:r:',
            ['usage', 'debug', 'ip=', 'port=', 'root='])
        for name, value in options:
            if name in ('-u', '--usage'):
                raise getopt.GetoptError
            if name in ('-d', '--debug'):
                DEBUG = True
                print('set debug mode on', flush=True)
            if name in ('-i', '--ip'):
                ip = value
                print('set ip to %s.' % ip, flush=True)
            if name in ('-p', '--port'):
                port = value
                print('set port to %s.' % port, flush=True)
            if name in ('-r', '--root'):
                ROOT_DIR = value
                print('set root dir to %s.' % ROOT_DIR, flush=True)
    except getopt.GetoptError:
        print('usage: python3 server.py [-d] [-i ip] [-p port] [-r root]',
              flush=True)
        sys.exit(2)

    # 设置日志格式
    if DEBUG:
        # 设置日志级别
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'
        )
    else:
        print('set log file to log.txt', flush=True)
        logging.basicConfig(
            level=logging.INFO,
            filename='log.txt',
            filemode='w',
            format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'
        )

    # 启动服务器
    main(ip, port)
