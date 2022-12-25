from socket import *
from threading import Thread
import time

import pymysql
from openpyxl import load_workbook
from ChatingRoom import SM
from gmssl import sm2

BLOCK_SIZE = 16


def getTime():
    return '[' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + ']'


def main():
    # 获取本机IP
    hostname = gethostname()
    ip = gethostbyname(hostname)
    print(getTime(), "服务器IP：" + ip)
    server1 = Server((ip, 65535))
    server1.start()


class Server:
    # 在线清单
    user_online = []
    online_user_name = {}  # 用户名\IP\端口
    online_user_ip = {}  # 用户IP
    users_keys = {}  # 用户名:[AES密钥, 公钥, 私钥]
    users_sm2 = {}  # 用户名:sm2对象
    server_keys = []

    ServerStat = True

    def __init__(self, post):

        self.ServerPort = post
        self.UDP_socket = socket(AF_INET, SOCK_DGRAM)
        self.UDP_socket.bind(self.ServerPort)
        self.get_keys()
        self.sm2 = sm2.CryptSM2(public_key=self.server_keys[0], private_key=self.server_keys[1])
        self.thread_rece = Thread(target=self.recv_msg)

    def start(self):
        print(getTime(), '服务端已启动')
        self.thread_rece.start()
        self.thread_rece.join()

    def get_keys(self):
        while True:
            try:
                AES_key, public_key, private_key = SM.my_keys()
                ciphertext = SM.Enc_and_sign("进程已结束", AES_key, private_key)
                SM.Dec_and_verify(ciphertext, AES_key, public_key)
                self.server_keys.append(public_key)
                self.server_keys.append(private_key)
                break
            except TypeError:
                continue

    # def SM2_encrypt_and_AES_encrypt(self, AES_key, info_need_encrypt):
    #     info_encrypt = self.sm2.encrypt(info_need_encrypt.encode())
    #     info = b64encode(info_encrypt).decode()
    #     aes = AES.new(AES_key.encode(), AES.MODE_ECB)
    #     info_encrypt = aes.encrypt(pad(info.encode(), BLOCK_SIZE))
    #     return info_encrypt

    def recv_msg(self):
        # 接收信息
        while True:
            # 接收信息并转化成固定格式
            recv_data, send_add = self.UDP_socket.recvfrom(1024)  # 1024 表示接收最大字节  防止内存溢出
            if recv_data[-2:] == '^&'.encode():
                self.UDP_socket.sendto((self.server_keys[0] + '^&').encode(), send_add)
                d = ['_', '_']
                d[1] = recv_data[:-2].decode()

                recv_data, add = self.UDP_socket.recvfrom(1024)
                if add == send_add:
                    recv_data = recv_data.decode()
                    recv_data = SM.decrypt(recv_data, self.sm2)
                    info_list = recv_data.split('^&')
                    if len(info_list) != 3:
                        continue
                    user = info_list[1]
                    password = info_list[2]
                    print(getTime(), send_add, info_list)
                    # 判断是否重复登录
                    if user in self.online_user_name:
                        self.UDP_socket.sendto(
                            SM.Enc_and_sign('\n系统： 您已登录或该用户名已被注册！请输入exit退出并重新登录',
                                            info_list[0],
                                            self.server_keys[1]), send_add)
                        continue

                    # 数据库部分
                    users = {}
                    dbselect = pymysql.connect(host='localhost', user='root', password='root', database='gui_user')
                    cursor = dbselect.cursor()
                    sql = """SELECT * FROM  user;"""
                    cursor.execute(sql)
                    results = cursor.fetchall()
                    for row in results:
                        users[row[0]] = row[1]
                    cursor.close()
                    dbselect.close()

                    flag = 0
                    user_list = list(users.keys())
                    ped_list = list(users.values())
                    for i in range(len(users)):
                        if user == user_list[i]:
                            if password == ped_list[i]:
                                flag = 1
                                break
                            else:
                                self.UDP_socket.sendto(
                                    SM.Enc_and_sign('\n系统： 密码错误！请输入exit退出并重新登录', info_list[0],
                                                    self.server_keys[1]), send_add)
                                flag = -1
                                break

                    if flag == -1:
                        continue
                    elif flag == 0:
                        dbinsert = pymysql.connect(host='localhost', user='root', password='root', database='gui_user')
                        cursor = dbinsert.cursor()
                        sql = "insert into user(username, password) values ('%s','%s')" % (user, password)
                        cursor.execute(sql)
                        dbinsert.commit()
                        cursor.close()
                        dbinsert.close()

                        # 此段和flag == 1v一致
                        self.online_user_name[user] = send_add
                        self.online_user_ip[send_add] = user
                        self.user_online.append(user)
                        d[0] = info_list[0]
                        self.users_keys[user] = d
                        self.users_sm2[user] = sm2.CryptSM2(private_key='', public_key=d[1])
                        self.UDP_socket.sendto(SM.Enc_and_sign(
                            '系统： 注册成功！已加入聊天\n功能说明：\n1.私聊：消息 + “-to” +对方id\n2.@全员成员：消息 + '
                            '“-ta”\n3.退出聊天：Exit\n开始输入消息吧!\n',
                            info_list[0], self.server_keys[1]), send_add)
                        # 更新表
                        self.update_users_onlinelist()
                        self.sent_to_all_notMe(send_add, getTime() + '系统：%s加入了聊天！\n' % info_list[1])

                    elif flag == 1:
                        self.online_user_name[user] = send_add
                        self.online_user_ip[send_add] = user
                        self.user_online.append(user)

                        d[0] = info_list[0]
                        self.users_keys[user] = d
                        self.users_sm2[user] = sm2.CryptSM2(private_key='', public_key=d[1])
                        self.UDP_socket.sendto(SM.Enc_and_sign(
                            '系统： 登录成功！已加入聊天\n功能说明：\n1.私聊：消息 + “-to” +对方id\n2.@全员成员：消息 + '
                            '“-ta”\n3.退出聊天：Exit\n开始输入消息吧!\n',
                            info_list[0], self.server_keys[1]), send_add)
                        # 更新表
                        self.update_users_onlinelist()
                        self.sent_to_all_notMe(send_add, getTime() + '系统：%s加入了聊天！\n' % info_list[1])
                continue

            recv_plaintext = SM.Dec_and_verify(recv_data, self.users_keys[self.online_user_ip[send_add]][0],
                                               self.users_keys[self.online_user_ip[send_add]][1])
            if not recv_plaintext:
                continue
            info_list = str(recv_plaintext).split(' ')

            # 显示接收到的信息
            print(getTime(), send_add, ' '.join(info_list))

            # 1.私发
            if len(info_list) >= 3 and info_list[-2] == '-to':
                # 若在在线清单里目前查询不到目标用户，则回复警告
                if info_list[-1] not in self.online_user_name.keys():
                    enroll_info_ = SM.Enc_and_sign(getTime() + '系统：发送失败！该用户不在线！\n',
                                                   self.users_keys[self.online_user_ip[send_add]][0],
                                                   self.server_keys[1])
                    self.UDP_socket.sendto(enroll_info_, send_add)
                    continue  # 跳出循环接收下一条信息

                # 若查询到了目标用户
                dest_port = self.online_user_name[info_list[-1]]  # 接收方端口
                enroll_info_ = SM.Enc_and_sign(
                    getTime() + ' %s对你说：' % self.online_user_ip[send_add] + ' '.join(info_list[:-2]),
                    self.users_keys[info_list[-1]][0], self.server_keys[1])  # 需发送的信息
                self.UDP_socket.sendto(enroll_info_, dest_port)
                ans_info = SM.Enc_and_sign(
                    getTime() + ' 已发送',
                    self.users_keys[self.online_user_ip[send_add]][0], self.server_keys[1])  # 需发送的信息
                self.UDP_socket.sendto(ans_info, send_add)
                continue
            elif len(info_list) == 2:
                # 3.@全体成员
                if info_list[-1] == '-ta':
                    if len(self.online_user_name) == 1:
                        self.UDP_socket.sendto(
                            SM.Enc_and_sign(getTime() + '系统：无其他用户在线！\n',
                                            self.users_keys[self.online_user_ip[send_add]][0], self.server_keys[1]),
                            send_add)
                        continue
                    # 群发消息
                    self.sent_to_all_notMe(send_add,
                                           getTime() + ' %s@全体成员：' % self.online_user_ip[send_add] + ' '.join(
                                               info_list[:-1]))
                    ans_info = SM.Enc_and_sign(
                        getTime() + ' 已发送',
                        self.users_keys[self.online_user_ip[send_add]][0], self.server_keys[1])  # 需发送的信息
                    self.UDP_socket.sendto(ans_info, send_add)
                else:
                    self.error(send_add)
            elif len(info_list) == 1:
                # 4.正常退出
                if recv_plaintext == 'Exit':
                    self.UDP_socket.sendto(
                        SM.Enc_and_sign('Exit', self.users_keys[self.online_user_ip[send_add]][0], self.server_keys[1]),
                        send_add)
                    name = self.online_user_ip.pop(send_add)
                    del self.online_user_name[name]
                    del self.users_keys[name]
                    del self.users_sm2[name]
                    # 删除退出登录的用户并更新在线用户列表
                    self.user_online.remove(name)
                    self.update_users_onlinelist()
                    self.sent_to_all(getTime() + '系统：%s已退出聊天\n' % name)
                else:
                    self.error(send_add)
            else:
                self.error(send_add)

            if not len(self.online_user_name):
                for t in range(5):
                    print(getTime(), "服务器还有%s秒钟关闭" % (5 - t))
                    time.sleep(1)
                print(getTime(), "服务器关闭")
                self.UDP_socket.close()
                break

    def update_users_onlinelist(self):
        username = self.user_online
        dbupdate = pymysql.connect(host='localhost', user='root', password='root', database='gui_user')
        cursor = dbupdate.cursor()
        sqldelete = "DROP TABLE IF EXISTS user_online;"
        sqlcreate = "CREATE TABLE `gui_user`.`user_online`  (`id` int NOT NULL AUTO_INCREMENT,`user` varchar(255) NOT NULL,PRIMARY KEY (`id`));"
        cursor.execute(sqldelete)
        cursor.execute(sqlcreate)
        for i in range(len(username)):
            sql = "insert into user_online(id, user) values ('%s', '%s')" % (0, username[i])
            cursor.execute(sql)
            dbupdate.commit()
        cursor.close()
        dbupdate.close()

    # 要改
    def error(self, dest_add):
        error_info = SM.Enc_and_sign(getTime() + '系统：您的指令无效！\n',
                                     self.users_keys[self.online_user_ip[dest_add]][0], self.server_keys[1])
        self.UDP_socket.sendto(error_info, dest_add)

    def sent_to_all(self, enroll_info):
        # 广播信息
        if len(self.online_user_ip):
            for i in self.online_user_ip.keys():
                enroll_info_ = SM.Enc_and_sign(enroll_info, self.users_keys[self.online_user_ip[i]][0],
                                               self.server_keys[1])
                self.UDP_socket.sendto(enroll_info_, i)
        else:
            print(getTime(), '系统：已无在线用户！')

    def sent_to_all_notMe(self, send_ip, info):
        # 广播消息除了指定用户
        if len(self.online_user_ip):
            print(len(self.online_user_ip))
            for i in self.online_user_ip.keys():
                if i != send_ip:
                    info_ = SM.Enc_and_sign(info, self.users_keys[self.online_user_ip[i]][0], self.server_keys[1])
                    self.UDP_socket.sendto(info_, i)
        else:
            print(getTime(), '系统：已无在线用户！')


if __name__ == '__main__':
    main()
