import sys
import socket
import hashlib
import webbrowser
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.uic import loadUi
from os import getenv
from dotenv import load_dotenv

CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class LoginPage(QDialog):
    def __init__(self):
        super(LoginPage,self).__init__()
        loadUi(r'C:\Users\deadb\Documents\GitHub\AvailData\login_page\login_page.ui',self)
        self.login_button.clicked.connect(self.login_function)
        self.linkedin_button.clicked.connect(self.open_linkedin)


    def login_function(self):
        global CLIENT                                  
        username = str(self.username_line_edit.text())
        password = str(self.password_line_edit.text())
        enc_password = hashlib.sha256(password.encode()).hexdigest()
        self.username_line_edit.setText("")
        self.password_line_edit.setText("")

        if username != "" and password !="":
            CLIENT.send(username.encode())
            CLIENT.send(enc_password.encode())

            response = CLIENT.recv(1024).decode()
            if response == "True":
                #Switch to main screen and keep connection open
                print("Success")
            else:
                CLIENT.shutdown(socket.SHUT_RDWR)
                CLIENT.close()
                CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port"))))
                print("Failed")
        else:
            print("Verification failed! (Local)")


    def open_linkedin(self):
        webbrowser.open('www.linkedin.com/in/kolby-macdonald')


def env_configure():
    load_dotenv()


def main():

    env_configure()

    CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port"))))

    app=QApplication(sys.argv)
    mainwindow = LoginPage()
    widget=QtWidgets.QStackedWidget()
    widget.addWidget(mainwindow)
    widget.resize(1080,720)
    widget.setMaximumWidth(1920)
    widget.setMaximumHeight(1080)
    widget.show()
    app.exec_()


main()