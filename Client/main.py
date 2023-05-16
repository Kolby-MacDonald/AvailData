import sys
import webbrowser
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.uic import loadUi
import socket
import hashlib
from dotenv import load_dotenv
import os

CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class LoginPage(QDialog):
    def __init__(self):
        super(LoginPage,self).__init__()
        loadUi(r'C:\Users\deadb\Documents\GitHub\AvailData\login_page\login_page.ui',self)
        self.login_button.clicked.connect(self.login_function)
        self.linkedin_button.clicked.connect(self.open_linkedin)


    def login_function(self):
        global CLIENT                                                           # GET MOST RECENT CLIENT DEFINTION                                     
        username = str(self.username_line_edit.text())                          # GET VARIABLES FROM GUI
        password = str(self.password_line_edit.text())
        enc_password = hashlib.sha256(password.encode()).hexdigest()            # ENCRYPT THE PASSWORD (CLIENT SIDE HASHING)
        self.username_line_edit.setText("")
        self.password_line_edit.setText("")

        if username != "" and password !="":
            CLIENT.send(username.encode())
            CLIENT.send(enc_password.encode())
            print(CLIENT.recv(1024).decode())
            CLIENT.shutdown(socket.SHUT_RDWR)                                   # SHUTDOWN SOCKET TO GAURENTEE DATA TRANSFER
            CLIENT.close()                                                      # CLOSE THE SOCKET
            CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)          # RE-DEFINE THE SOCKET
            CLIENT.connect((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))   # GIVE CONNECTION ADDRESS TO SOCKET
        else:
            print("Verification failed! (Local)")

    
    def open_linkedin(self):
        webbrowser.open('www.linkedin.com/in/kolby-macdonald')


def configure():
    load_dotenv()


def main():

    configure()

    CLIENT.connect((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))

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