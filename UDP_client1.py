from socket import *
import time
from ChatingRoom import SM
from gmssl import sm2
import sys
import pymysql
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QHeaderView, QTableWidgetItem, QDialog, QLabel

global recv_data, send_data
global ClientPort, ServerPost, UDP_socket, UserName, PassWord

my_keys = []
server_key = 0


def get_keys():
    while True:
        try:
            AES_key, public_key, private_key = SM.my_keys()
            ciphertext = SM.Enc_and_sign("进程已结束", AES_key, private_key)
            SM.Dec_and_verify(ciphertext, AES_key, public_key)
            time.sleep(0.1)
            my_keys.append(AES_key)
            my_keys.append(public_key)
            my_keys.append(private_key)
            break
        except TypeError:
            continue


def setParams(name, password, client_post, server_post):
    global ClientPort, ServerPost, UDP_socket, UserName, PassWord
    # 初始化
    get_keys()
    ClientPort = client_post
    ServerPost = server_post
    UDP_socket = socket(AF_INET, SOCK_DGRAM)
    UserName = name
    PassWord = password


def establish_connection():
    # 运行
    UDP_socket.bind(ClientPort)
    UDP_socket.sendto((my_keys[1] + '^&').encode(), ServerPost)
    recv_data, from_add = UDP_socket.recvfrom(1024)
    if recv_data[-2:] == '^&'.encode() and from_add == ServerPost:
        server_key = recv_data.decode()[:-2]
        data_info = my_keys[0] + '^&' + UserName + '^&' + PassWord
        sm2_ = sm2.CryptSM2(public_key=server_key, private_key='')
        UDP_socket.sendto(SM.encrypt(data_info, sm2_).encode(), ServerPost)


def client_send_msg(input_info):
    if ClientPort:
        if input_info == 'Exit':
            UDP_socket.sendto(SM.Enc_and_sign(input_info, my_keys[0], my_keys[2]), ServerPost)
        elif input_info == 'exit':
            UDP_socket.close()
        else:
            UDP_socket.sendto(SM.Enc_and_sign(input_info, my_keys[0], my_keys[2]), ServerPost)


class client_recv_msg(QThread):
    recv_data = pyqtSignal(str)

    def run(self):
        # 接收信息
        while True:
            recv_data, from_add = UDP_socket.recvfrom(1024)
            info = SM.Dec_and_verify(recv_data, my_keys[0], server_key)
            if not info:
                continue
            if from_add == ServerPost:
                if info == 'Exit':
                    UDP_socket.close()
                    break
                elif info == '\033[31m\n系统： 您已登录或该用户名已被注册！请输入exit退出并重新登录' or info == '\033[31m\n系统： 密码错误！请输入exit退出并重新登录':
                    ui.showdialog()
                    ui.lineEdit_Password.clear()
                    ui.lineEdit_User.clear()
                    ui.lineEdit_Port.clear()
                    break
                else:
                    if "对你说：" in info:
                        ui.textEdit.append(info)
                    elif "@全体成员：" in info:
                        ui.textEdit_2.append(info)
                    else:
                        ui.textEdit.append(info)
                        ui.textEdit_2.append(info)


class update(QThread):

    def run(self):
        # 更新在线用户列表
        while True:
            ui.updateUserState()
            time.sleep(1)


class Ui_Window(object):
    def setupUi(self, Window):
        Window.setObjectName("Window")
        Window.resize(850, 560)
        Window.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.stackedWidget = QtWidgets.QStackedWidget(Window)
        self.stackedWidget.setGeometry(QtCore.QRect(0, 0, 860, 560))
        self.stackedWidget.setObjectName("stackedWidget")

        # 登录界面
        self.page_1Login = QtWidgets.QWidget()
        self.page_1Login.setObjectName("page_1Login")
        self.lineEdit_User = QtWidgets.QLineEdit(self.page_1Login)
        self.lineEdit_User.setGeometry(QtCore.QRect(340, 245, 320, 45))
        self.lineEdit_User.setObjectName("lineEdit_User")
        self.lineEdit_Password = QtWidgets.QLineEdit(self.page_1Login)
        self.lineEdit_Password.setGeometry(QtCore.QRect(340, 315, 320, 45))
        self.lineEdit_Password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_Password.setObjectName("lineEdit_Password")
        self.lineEdit_Port = QtWidgets.QLineEdit(self.page_1Login)
        self.lineEdit_Port.setGeometry(QtCore.QRect(340, 380, 320, 45))
        self.lineEdit_Port.setObjectName("lineEdit_Port")
        self.pushButton_Enter = QtWidgets.QPushButton(self.page_1Login)
        self.pushButton_Enter.setGeometry(QtCore.QRect(460, 450, 85, 40))
        self.pushButton_Enter.setStyleSheet("font: 12pt \"Microsoft YaHei UI\"")
        self.pushButton_Enter.setObjectName("pushButton_Enter")
        self.label_Art = QtWidgets.QLabel(self.page_1Login)
        self.label_Art.setGeometry(QtCore.QRect(390, 115, 220, 90))
        font = QtGui.QFont()
        font.setFamily("Lucida Handwriting")
        font.setPointSize(36)
        self.label_Art.setFont(font)
        self.label_Art.setTextFormat(QtCore.Qt.RichText)
        self.label_Art.setObjectName("label_Art")
        self.toolButton_close1 = QtWidgets.QToolButton(self.page_1Login)
        self.toolButton_close1.setGeometry(QtCore.QRect(815, 0, 35, 35))
        self.toolButton_close1.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.toolButton_close1.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("pic/叉叉.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.toolButton_close1.setIcon(icon)
        self.toolButton_close1.setIconSize(QtCore.QSize(28, 28))
        self.toolButton_close1.setObjectName("toolButton_close1")
        self.label_decorate1 = QtWidgets.QLabel(self.page_1Login)
        self.label_decorate1.setGeometry(QtCore.QRect(0, 10, 159, 36))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_decorate1.setFont(font)
        self.label_decorate1.setStyleSheet("border-width: 0.5px;\n"
                                           "border-style: solid;\n"
                                           "border-top: none;\n"
                                           "border-right: none;\n"
                                           "border-left: none;\n"
                                           "border-right-color: rgb(79, 79, 79);")
        self.label_decorate1.setObjectName("label_decorate1")
        self.tableWidget_1 = QtWidgets.QTableWidget(self.page_1Login)
        self.tableWidget_1.setGeometry(QtCore.QRect(0, 46, 159, 514))
        # self.tableWidget_1.setRowCount(1)
        self.tableWidget_1.setColumnCount(2)
        self.tableWidget_1.setObjectName("tableWidget_1")
        self.stackedWidget.addWidget(self.page_1Login)

        # 主界面
        self.page_2Main = QtWidgets.QWidget()
        self.page_2Main.setObjectName("page_2Main")
        self.toolButton_close3 = QtWidgets.QToolButton(self.page_2Main)
        self.toolButton_close3.setGeometry(QtCore.QRect(815, 0, 35, 35))
        self.toolButton_close3.setText("")
        self.toolButton_close3.setIcon(icon)
        self.toolButton_close3.setIconSize(QtCore.QSize(28, 28))
        self.toolButton_close3.setObjectName("toolButton_close3")
        self.label_Choice = QtWidgets.QLabel(self.page_2Main)
        self.label_Choice.setGeometry(QtCore.QRect(215, 70, 475, 45))
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(29)
        self.label_Choice.setFont(font)
        self.label_Choice.setObjectName("label_Choice")
        self.label_choose = QtWidgets.QLabel(self.page_2Main)
        self.label_choose.setGeometry(QtCore.QRect(272, 170, 750, 45))
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(24)
        self.label_choose.setFont(font)
        self.label_choose.setObjectName("label_choose")
        self.pushButton_Private = QtWidgets.QPushButton(self.page_2Main)
        self.pushButton_Private.setGeometry(QtCore.QRect(300, 330, 125, 42))
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(16)
        self.pushButton_Private.setFont(font)
        self.pushButton_Private.setObjectName("pushButton_Private")
        self.pushButton_Public = QtWidgets.QPushButton(self.page_2Main)
        self.pushButton_Public.setGeometry(QtCore.QRect(480, 330, 125, 42))
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(16)
        self.pushButton_Public.setFont(font)
        self.pushButton_Public.setObjectName("pushButton_Public")
        self.stackedWidget.addWidget(self.page_2Main)

        # 私聊页面
        self.page_3Private = QtWidgets.QWidget()
        self.page_3Private.setObjectName("page_3Private")
        self.tableWidget_2 = QtWidgets.QTableWidget(self.page_3Private)
        self.tableWidget_2.setGeometry(QtCore.QRect(0, 46, 159, 514))
        self.tableWidget_2.setGridStyle(QtCore.Qt.SolidLine)
        self.tableWidget_2.setRowCount(1)
        self.tableWidget_2.setColumnCount(2)
        self.tableWidget_2.setObjectName("tableWidget_2")
        self.label_decorate2 = QtWidgets.QLabel(self.page_3Private)
        self.label_decorate2.setGeometry(QtCore.QRect(0, 10, 159, 36))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_decorate2.setFont(font)
        self.label_decorate2.setStyleSheet("border-width: 0.5px;\n"
                                           "border-style: solid;\n"
                                           "border-top: none;\n"
                                           "border-right: none;\n"
                                           "border-left: none;\n"
                                           "border-right-color: rgb(79, 79, 79);")
        self.label_decorate2.setObjectName("label_decorate2")
        self.textEdit = QtWidgets.QTextEdit(self.page_3Private)
        self.textEdit.setGeometry(QtCore.QRect(300, 100, 400, 300))
        self.textEdit.setObjectName("textEdit")
        self.textEdit.setReadOnly(True)
        self.lineEdit = QtWidgets.QLineEdit(self.page_3Private)
        self.lineEdit.setGeometry(QtCore.QRect(300, 420, 400, 42))
        self.lineEdit.setObjectName("lineEdit")
        self.toolButton_close2 = QtWidgets.QToolButton(self.page_3Private)
        self.toolButton_close2.setGeometry(QtCore.QRect(815, 0, 35, 35))
        self.toolButton_close2.setText("")
        self.toolButton_close2.setIcon(icon)
        self.toolButton_close2.setIconSize(QtCore.QSize(28, 28))
        self.toolButton_close2.setObjectName("toolButton_close2")
        self.label_title1 = QtWidgets.QLabel(self.page_3Private)
        self.label_title1.setGeometry(QtCore.QRect(430, 30, 140, 35))
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(20)
        self.label_title1.setFont(font)
        self.label_title1.setObjectName("label_title1")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.page_3Private)
        self.lineEdit_3.setGeometry(QtCore.QRect(300, 482, 300, 42))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.pushButton = QtWidgets.QPushButton(self.page_3Private)
        self.pushButton.setGeometry(QtCore.QRect(605, 482, 95, 42))
        self.pushButton.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.pushButton.setObjectName("pushButton")
        self.toolButton_backtoall = QtWidgets.QToolButton(self.page_3Private)
        self.toolButton_backtoall.setGeometry(QtCore.QRect(180, 30, 35, 35))
        self.toolButton_backtoall.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.toolButton_backtoall.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("pic/返回.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.toolButton_backtoall.setIcon(icon1)
        self.toolButton_backtoall.setIconSize(QtCore.QSize(28, 28))
        self.toolButton_backtoall.setObjectName("toolButton_backtoall")
        self.stackedWidget.addWidget(self.page_3Private)

        # 公聊界面
        self.page_4Public = QtWidgets.QWidget()
        self.page_4Public.setObjectName("page_4Public")
        self.toolButton_close4 = QtWidgets.QToolButton(self.page_4Public)
        self.toolButton_close4.setGeometry(QtCore.QRect(815, 0, 35, 35))
        self.toolButton_close4.setText("")
        self.toolButton_close4.setIcon(icon)
        self.toolButton_close4.setIconSize(QtCore.QSize(28, 28))
        self.toolButton_close4.setObjectName("toolButton_close4")
        self.label_decorate3 = QtWidgets.QLabel(self.page_4Public)
        self.label_decorate3.setGeometry(QtCore.QRect(0, 10, 159, 36))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_decorate3.setFont(font)
        self.label_decorate3.setStyleSheet("border-width: 0.5px;\n"
                                           "border-style: solid;\n"
                                           "border-top: none;\n"
                                           "border-right: none;\n"
                                           "border-left: none;\n"
                                           "border-right-color: rgb(79, 79, 79);")
        self.label_decorate3.setObjectName("label_decorate3")
        self.tableWidget_3 = QtWidgets.QTableWidget(self.page_4Public)
        self.tableWidget_3.setGeometry(QtCore.QRect(0, 46, 159, 514))
        self.tableWidget_3.setGridStyle(QtCore.Qt.SolidLine)
        self.tableWidget_3.setRowCount(1)
        self.tableWidget_3.setColumnCount(2)
        self.tableWidget_3.setObjectName("tableWidget_3")
        self.textEdit_2 = QtWidgets.QTextEdit(self.page_4Public)
        self.textEdit_2.setGeometry(QtCore.QRect(300, 100, 400, 330))
        self.textEdit_2.setObjectName("textEdit_2")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.page_4Public)
        self.lineEdit_2.setGeometry(QtCore.QRect(300, 460, 400, 42))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.textEdit_2.setReadOnly(True)
        self.label_title2 = QtWidgets.QLabel(self.page_4Public)
        self.label_title2.setGeometry(QtCore.QRect(430, 30, 140, 35))
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(20)
        self.label_title2.setFont(font)
        self.label_title2.setObjectName("label_title2")
        self.toolButton_backtoone = QtWidgets.QToolButton(self.page_4Public)
        self.toolButton_backtoone.setGeometry(QtCore.QRect(180, 30, 35, 35))
        self.toolButton_backtoone.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.toolButton_backtoone.setText("")
        self.toolButton_backtoone.setIcon(icon1)
        self.toolButton_backtoone.setIconSize(QtCore.QSize(28, 28))
        self.toolButton_backtoone.setObjectName("toolButton_backtoone")
        self.stackedWidget.addWidget(self.page_4Public)

        # 显示用户
        self.updateUserState()

        # 命名/槽函数
        self.retranslateUi(Window)
        self.pushButton_Enter.clicked.connect(self.changePageEnter)
        self.pushButton_Private.clicked.connect(self.changePagePrivate)
        self.pushButton_Public.clicked.connect(self.changePagePublic)
        self.toolButton_backtoone.clicked.connect(self.changePagePrivate)
        self.toolButton_backtoall.clicked.connect(self.changePagePublic)
        self.pushButton.clicked.connect(self.sendToOne)
        self.lineEdit_2.returnPressed.connect(self.sendToAll)
        self.toolButton_close1.clicked.connect(Window.close)
        self.toolButton_close2.clicked.connect(Window.close)
        self.toolButton_close3.clicked.connect(Window.close)
        self.toolButton_close4.clicked.connect(Window.close)
        QtCore.QMetaObject.connectSlotsByName(Window)

    def retranslateUi(self, Window):
        _translate = QtCore.QCoreApplication.translate
        Window.setWindowTitle(_translate("Window", "聊天应用"))
        self.lineEdit_User.setPlaceholderText(_translate("Window", " 用户名："))
        self.lineEdit_Password.setPlaceholderText(_translate("Window", " 密码："))
        self.lineEdit_Port.setPlaceholderText(_translate("Window", " 端口号："))
        self.pushButton_Enter.setText(_translate("Window", "登录"))
        self.label_Art.setText(_translate("Window", "Login"))
        self.label_decorate1.setText(_translate("Window", " 在线用户"))
        self.label_Choice.setText(_translate("Window", "欢迎进入聊天室 ！！！"))
        self.label_choose.setText(_translate("Window", "请选择以下聊天模式"))
        self.pushButton_Private.setText(_translate("Window", "私聊模式"))
        self.pushButton_Public.setText(_translate("Window", "群聊模式"))
        self.label_decorate2.setText(_translate("Window", " 在线用户"))
        self.lineEdit.setPlaceholderText(_translate("Window", " 请输入要发送的信息"))
        self.label_title1.setText(_translate("Window", "私聊模式"))
        self.lineEdit_3.setPlaceholderText(_translate("Window", " 请输入要发送的对象"))
        self.pushButton.setText(_translate("Window", "点击发送"))
        self.label_decorate3.setText(_translate("Window", " 在线用户"))
        self.lineEdit_2.setPlaceholderText(_translate("Window", " 请输入要发送的信息"))
        self.label_title2.setText(_translate("Window", "群聊模式"))

    def setNoTitle(self, Window):
        Window.setWindowFlags(Qt.FramelessWindowHint)

    def changePageMain(self):
        self.stackedWidget.setCurrentIndex(1)

    def changePagePrivate(self):
        self.stackedWidget.setCurrentIndex(2)
        self.updateUserState()

    def changePagePublic(self):
        self.stackedWidget.setCurrentIndex(3)
        self.updateUserState()

    def getUsers(self):
        users = {}
        db = pymysql.connect(host='localhost', user='root', password='root', database='gui_user')
        cursor = db.cursor()
        sql = """SELECT * FROM  user;"""
        cursor.execute(sql)
        results = cursor.fetchall()
        for row in results:
            users[row[0]] = row[1]
        db.close()
        return users

    def updateUserState(self):
        users = list(self.getUsers().keys())
        row = len(users)

        users_online = []
        db = pymysql.connect(host='localhost', user='root', password='root', database='gui_user')
        cursor = db.cursor()
        sql = """SELECT user FROM  user_online;"""
        cursor.execute(sql)
        results = cursor.fetchall()
        for single in results:
            users_online.append(single[0])
        cursor.close()
        db.close()

        sorted_list = [m for m in users_online]
        for m in users:
            if m not in sorted_list:
                sorted_list.append(m)

        self.tableWidget_1.setRowCount(row)
        self.tableWidget_2.setRowCount(row)
        self.tableWidget_3.setRowCount(row)
        self.tableWidget_1.setHorizontalHeaderLabels(["用户", "状态"])
        self.tableWidget_2.setHorizontalHeaderLabels(["用户", "状态"])
        self.tableWidget_3.setHorizontalHeaderLabels(["用户", "状态"])
        self.tableWidget_1.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget_2.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget_3.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        for i in range(row):
            self.tableWidget_1.setItem(i, 0, QTableWidgetItem("  " + users[i]))
            self.tableWidget_1.setItem(i, 1, QTableWidgetItem(" ——"))
            if sorted_list[i] in users_online:
                self.tableWidget_2.setItem(i, 0, QTableWidgetItem(sorted_list[i]))
                self.tableWidget_2.setItem(i, 1, QTableWidgetItem(" 在线"))
                self.tableWidget_3.setItem(i, 0, QTableWidgetItem(sorted_list[i]))
                self.tableWidget_3.setItem(i, 1, QTableWidgetItem(" 在线"))
            else:
                self.tableWidget_2.setItem(i, 0, QTableWidgetItem(sorted_list[i]))
                self.tableWidget_2.setItem(i, 1, QTableWidgetItem(" 离线"))
                self.tableWidget_3.setItem(i, 0, QTableWidgetItem(sorted_list[i]))
                self.tableWidget_3.setItem(i, 1, QTableWidgetItem(" 离线"))

    def showdialog(self):
        dialog = QDialog()
        font = QtGui.QFont()
        font.setFamily("方正舒体")
        font.setPointSize(12)
        lab = QLabel("重复登录或密码错误\n请重新登录！！！", dialog)
        lab.move(100, 100)
        lab.setFont(font)
        dialog.setWindowTitle("Dialog")
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.exec_()

    def getFlag(self):
        global name, password, Post_num
        flag = [False, False, False]
        name = ui.lineEdit_User.text()
        if name == '' or ' ' in name:
            ui.lineEdit_User.clear()
            ui.lineEdit_User.setPlaceholderText(" 请输入有效的用户名")
        else:
            flag[0] = True

        password = ui.lineEdit_Password.text()
        if password == '' or ' ' in password:
            ui.lineEdit_Password.clear()
            ui.lineEdit_Password.setPlaceholderText(" 请输入有效的密码")
        else:
            flag[1] = True

        Post_num = ui.lineEdit_Port.text()
        if Post_num == '' or ' ' in Post_num:
            ui.lineEdit_Port.clear()
            ui.lineEdit_Port.setPlaceholderText(" 请输入有效的端口号")
        else:
            flag[2] = True

        if Post_num:
            Post_num = int(Post_num)

        return flag

    # 主功能函数
    def changePageEnter(self):
        flag = self.getFlag()
        if False not in flag:
            self.stackedWidget.setCurrentIndex(1)
            # 获取本机IP
            hostname = gethostname()
            ip = gethostbyname(hostname)
            setParams(name, password, (ip, Post_num), (ip, 65535))
            establish_connection()
            self.back_recv = client_recv_msg()
            self.back_recv.recv_data.connect(self.dataProcess)
            self.back_up = update()
            self.back_recv.start()
            self.back_up.start()

    def dataProcess(self, data):
        count = 0
        data = data.split("：")
        for m in data:
            if "@全体成员" in m:
                count += 1
        if count == 1:
            self.textEdit_2.append(data)
        else:
            self.textEdit.append(data)

    def sendToOne(self):
        input_info = ui.lineEdit.text()
        obj = ui.lineEdit_3.text()
        ui.lineEdit.clear()
        ui.lineEdit_3.clear()
        input_info = input_info + " -to " + obj
        client_send_msg(input_info)

    def sendToAll(self):
        input_info = ui.lineEdit_2.text()
        ui.lineEdit_2.clear()
        if input_info == "Exit" or input_info == "exit":
            client_send_msg(input_info)
            self.toolButton_close3.click()
        else:
            input_info = input_info + " -ta"
            client_send_msg(input_info)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_Window()
    ui.setNoTitle(MainWindow)
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
