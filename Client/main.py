import sys
import json
import socket
import hashlib
import webbrowser
import pandas as pd
from os import getenv
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from dotenv import load_dotenv
from PyQt5.QtWidgets import QDialog, QApplication

import rsa

CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

################################################## LOG IN CLASS #######################################################

class LoginPage(QDialog):
    
    def __init__(self):
        super(LoginPage,self).__init__()
        loadUi(r'Client\pages\login_page.ui', self)
        self.login_button.clicked.connect(self.login_function)
        self.signup_button.clicked.connect(self.open_signup_page)
        self.linkedin_button.clicked.connect(self.open_linkedin)

    def login_function(self):
        global CLIENT

        username = str(self.username_line_edit.text())
        password = str(self.password_line_edit.text())
        enc_password = hashlib.sha256(password.encode()).hexdigest()
        
        self.username_line_edit.setText("")
        self.password_line_edit.setText("")

        if username != "" and password !="":
            request = "login"
            data = [request, username, enc_password]
            send_data(data)
            #CLIENT.sendall(username.encode())
            #CLIENT.sendall(enc_password.encode())

            response = recieve_data()
            print(response)
            #response = CLIENT.recv(1024).decode()

            if response == "True":
                self.open_user_page()

            else:
                CLIENT.shutdown(socket.SHUT_RDWR)
                CLIENT.close()
                CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port"))))
                print("Failed")
        else:
            print("Enter your credentials to login.")

    def open_linkedin(self):
        webbrowser.open('www.linkedin.com/in/kolby-macdonald')

    def open_signup_page(self):
        widget.removeWidget(login_window)
        widget.addWidget(signup_window)

    def open_user_page(self):
        user_window = UserPage()
        widget.removeWidget(login_window)
        widget.addWidget(user_window)

################################################## SIGN UP CLASS ######################################################

class SignUpPage(QDialog): 
    def __init__(self):
        super(SignUpPage,self).__init__()
        loadUi(r'Client\pages\signup_page.ui',self)
        self.submit_button.clicked.connect(self.signup_function)
        self.return_button.clicked.connect(self.open_login_page)

    def signup_function(self):
        username = self.username_line_edit.text()
        email = self.email_line_edit.text()
        password = self.password_line_edit.text()
        confirm_password = self.confirm_password_line_edit.text()
        print(f"username = {username} | email = {email} | password = {password} | confirm_password = {confirm_password}")
    
    def open_login_page(self):
        widget.removeWidget(signup_window)
        widget.addWidget(login_window)

##################################################### USER'S MAIN PAGE ################################################

class UserPage(QDialog):

    def __init__(self):
        super(UserPage, self).__init__()
        loadUi(r'Client\pages\user_page_test.ui', self)
        self.table_select_combobox.currentIndexChanged.connect(lambda: UserPage.request_handler(self, "update_loaded_table"))
        self.result_select_combobox.currentIndexChanged.connect(lambda: UserPage.request_handler(self, "update_loaded_table"))
        self.logout_button.clicked.connect(lambda: UserPage.request_handler(self, "log_out"))
        self.loaded_table_edit

        UserPage.request_handler(self, "get_init_data")

    ######################################## CLIENT REQUEST FUNCTIONS #################################################

    def request_handler(self, request):

        if request == "get_init_data":
            data = [request]
            send_data(data)
            user_table_names = recieve_data()
            UserPage.get_init_data(self, user_table_names)

        elif request == "update_loaded_table":
            data = [request, self.table_select_combobox.currentText(), self.result_select_combobox.currentText()]
            send_data(data)
            table_data = recieve_data()
            UserPage.update_table_view(self, table_data)
        
        elif request == "log_out":
            self.loaded_table_edit.clear()
            data = [request]
            send_data(data)
            user_window = self
            widget.removeWidget(user_window)
            widget.addWidget(login_window)

    ######################################## CLIENT UI FUNCTIONS ######################################################

    def get_init_data(self, user_table_names):

        if user_table_names != []:
            self.table_select_combobox.addItems(user_table_names[0])
        else:
            print("No Acessable Tables Found")
            pass

    def update_table_view(self, table_data):
        self.loaded_table_edit.clear()

        if table_data != []:
            
            table_data = table_data[0]
            df = pd.DataFrame.from_dict(table_data)
            column_titles = list(df.columns.values)
            column_titles = [str(title) for title in column_titles]

            self.loaded_table_edit.setColumnCount(len(df.columns))
            self.loaded_table_edit.setRowCount(len(df.index))
            self.loaded_table_edit.setHorizontalHeaderLabels(column_titles)

            for column, title in enumerate(column_titles):
                for row, item in enumerate(df[title]):
                    item = str(item)
                    if item == 'None':
                        item = ''
                    self.loaded_table_edit.setItem(row, column, QtWidgets.QTableWidgetItem(item))
        else:
            print("No Acessable Tables Found")


def send_data(data):
    json_data = json.dumps(data)
    data_length = len(json_data)
    header = f"{data_length:<{15}}".encode('utf-8')

    CLIENT.sendall(header + json_data.encode('utf-8'))


def recieve_data():
    try:
        header = CLIENT.recv(15)
        if not header:
            return None

        data_length = int(header.strip())
        data = CLIENT.recv(data_length).decode('utf-8')
        json_data = json.loads(data)
        return(json_data)
    except:
        pass


######################################### MAIN STARTUP SCRIPT #########################################################

load_dotenv()


CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port"))))
# SEND THE CLIENTS PUBLIC KEY


app=QApplication(sys.argv)
widget=QtWidgets.QStackedWidget()
login_window = LoginPage()
signup_window = SignUpPage()
widget.setWindowTitle("[ AvailData ]")
widget.addWidget(login_window)
widget.resize(1080,720)
widget.setMaximumWidth(1920)
widget.setMaximumHeight(1080)
widget.show()
app.exec_()