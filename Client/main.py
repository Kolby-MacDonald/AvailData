import os
import sys
import ssl
import json
import socket
import hashlib
import webbrowser
import pandas as pd
from OpenSSL import crypto
from PyQt5.QtCore import Qt
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from dotenv import load_dotenv
from PyQt5.QtWidgets import QDialog, QApplication, QTableWidgetItem, QAbstractItemView
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Global variables for server public key and client private key
server_public_key = None
client_private_key = None

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def encrypt_message(public_key, message):
    public_key = serialization.load_pem_public_key(public_key)
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(private_key, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key, password=None)
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Decrypted : {decrypted}")
    return decrypted

################################################## LOG IN CLASS #######################################################

class LoginPage(QDialog):
    
    def __init__(self):
        super(LoginPage,self).__init__()
        loadUi(r'Client\pages\login_page.ui', self)
        self.login_button.clicked.connect(self.login_function)
        self.signup_button.clicked.connect(self.open_signup_page)
        self.linkedin_button.clicked.connect(self.open_linkedin)

    def login_function(self):
        username = str(self.username_line_edit.text())
        password = str(self.password_line_edit.text())
        enc_password = hashlib.sha256(password.encode()).hexdigest()
        
        self.username_line_edit.setText("")
        self.password_line_edit.setText("")

        if username != "" and password !="":
            global CLIENT
            CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                # WRAP SOCKET IN SSL
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                if str(os.getenv("ca_cert_required")) == "True": 
                    cert_file = str(os.getenv("ca_cert_file"))
                    key_file =  str(os.getenv("ca_key_file"))
                    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                    CLIENT.connect((os.getenv("pub_ip"), int(os.getenv("pub_port"))))
                    context.load_verify_locations(str(os.getenv("ca_verify_file")))
                else:
                    cert_file = str(os.getenv("gen_cert_file"))
                    key_file =  str(os.getenv("gen_key_file"))
                    generate_ssl_certificate(cert_file, key_file)
                    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                    context.verify_mode = ssl.CERT_NONE
                    CLIENT = context.wrap_socket(CLIENT)
                    CLIENT.connect((os.getenv("pub_ip"), int(os.getenv("pub_port"))))

                global client_private_key, server_public_key
                client_private_key, client_public_key = generate_key_pair()

                CLIENT.sendall(client_public_key)
                server_public_key = CLIENT.recv(4096)

                data = ["login", username, enc_password]
                send_data(data)

                response = receive_data()

                if response == True:
                    self.open_user_page()
                else:
                    close_connection()
                    print("Failed")
    
            except Exception as err: print(f"Server Refused to Connect {err}")
            
        else:
            print("Enter your credentials to login.")

    def open_linkedin(self):
        webbrowser.open('www.linkedin.com/in/kolby-macdonald')

    def open_signup_page(self):
        widget.removeWidget(login_window)
        widget.addWidget(signup_window)

    def open_user_page(self):
        user_window = UserPage()
        widget.addWidget(user_window)
        widget.removeWidget(login_window)

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
        widget.addWidget(login_window)
        widget.removeWidget(signup_window)

##################################################### USER'S MAIN PAGE ################################################

class UserPage(QDialog):

    def __init__(self):
        super(UserPage, self).__init__()
        loadUi(r'Client\pages\user_page_test.ui', self)
        self.table_select_combobox.currentIndexChanged.connect(lambda: UserPage.request_handler(self, "update_loaded_table"))
        self.result_select_combobox.currentIndexChanged.connect(lambda: UserPage.request_handler(self, "update_loaded_table"))
        self.logout_button.clicked.connect(lambda: UserPage.request_handler(self, "log_out"))
        self.readwrite_radioButton.clicked.connect(lambda: UserPage.readwrite_table_control(self))

        UserPage.request_handler(self, "get_init_data")

    #----------------------------------------------- CLIENT REQUEST FUNCTIONS #---------------------------------------

    def request_handler(self, request):

        if request == "get_init_data":
            data = [request]
            send_data(data)
            user_table_names = receive_data()
            self.user_write_table_names = user_table_names[0]
            self.user_read_table_names = user_table_names[1]
            UserPage.get_init_data(self)

        elif request == "update_loaded_table":
            data = [request, self.table_select_combobox.currentText(), self.result_select_combobox.currentText()]
            send_data(data)
            table_data = receive_data()
            print(f"Data in request handler: {table_data}")
            UserPage.update_table_view(self, table_data)
        
        elif request == "log_out":
            self.loaded_table_edit.clear()
            close_connection()
            user_window = self
            widget.addWidget(login_window)
            widget.removeWidget(user_window)

    #----------------------------------------------- CLIENT UI FUNCTIONS -------------------------------------------
    def get_init_data(self):

        if self.user_write_table_names != [] or self.user_read_table_names != []:
            self.table_select_combobox.addItems(self.user_write_table_names + self.user_read_table_names)
        else:
            self.readwrite_radioButton.setChecked(False)
            self.readwrite_radioButton.setEnabled(False)
            self.readwrite_radioButton.setText("No Selection")

    def update_table_view(self, table_data):
        self.loaded_table_edit.clear()
        
        if self.table_select_combobox.currentText() not in self.user_write_table_names:
            self.readwrite_radioButton.setChecked(False)
            self.readwrite_radioButton.setEnabled(False)
            self.readwrite_radioButton.setText("Locked Table")
            self.readwrite_table_control()
        elif self.table_select_combobox.currentText() in self.user_write_table_names:
            self.readwrite_radioButton.setText("Edit Mode")
            self.readwrite_radioButton.setEnabled(True)
            self.readwrite_table_control()

        print(table_data)

        if table_data != []:
            table_data = table_data[0]
            df = pd.DataFrame.from_dict(table_data)
            column_titles = list(df.columns.values)
            column_titles = [str(title) for title in column_titles]

            self.loaded_table_edit.setColumnCount(len(df.columns))
            self.loaded_table_edit.setRowCount(len(df.index))
            self.loaded_table_edit.setHorizontalHeaderLabels(column_titles)
            self.loaded_table_edit.resizeColumnsToContents()

            # Add extra 15 pixels on either side
            for column in range(self.loaded_table_edit.columnCount()):
                width = self.loaded_table_edit.columnWidth(column)
                self.loaded_table_edit.setColumnWidth(column, width + 30)
            
            for row in range(self.loaded_table_edit.rowCount()):
                item = QTableWidgetItem(str(row + 1))
                item.setTextAlignment(Qt.AlignCenter)  # Qt.AlignCenter
                self.loaded_table_edit.setVerticalHeaderItem(row, item)

            for column, title in enumerate(column_titles):
                for row, item in enumerate(df[title]):
                    item = str(item)
                    if item == 'None':
                        item = ''
                    self.loaded_table_edit.setItem(row, column, QTableWidgetItem(item))

        else:
            print("No Acessable Tables Found")
    
    def readwrite_table_control(self):
        if self.readwrite_radioButton.isChecked():
            self.loaded_table_edit.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed)  # Enable editing
            self.loaded_table_edit.setSelectionMode(QAbstractItemView.ExtendedSelection)
        elif not self.readwrite_radioButton.isChecked():
            self.loaded_table_edit.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.loaded_table_edit.setSelectionMode(QAbstractItemView.NoSelection)
            self.loaded_table_edit.clearSelection()

######################################### SEND AND RECIEVE BUFFERED DATA ########################################

def send_data(data):
    global server_public_key
    json_data = json.dumps(data)
    encrypted_data = encrypt_message(server_public_key, json_data.encode('utf-8'))
    data_length = len(encrypted_data)
    header = f"{data_length:<{15}}".encode('utf-8')

    CLIENT.sendall(header + encrypted_data)

def receive_data():
    global client_private_key
    print("In receive_data")
    try:
        header = CLIENT.recv(15)
        if not header:
            return None

        data_length = int(header.strip())
        encrypted_data = CLIENT.recv(data_length)
        print(f"encrypted_data = {encrypted_data}")
        json_data = decrypt_message(client_private_key, encrypted_data)
        decoded_data = json_data.decode('utf-8')
        json_data = json.loads(decoded_data)
        print(f"returning: {json_data}")
        return json_data
    except Exception as err_msg:
        print(f"ERROR IN RECV DATA: {err_msg}")

def close_connection():
    global CLIENT
    data = ["log_out"]
    send_data(data)
    CLIENT.shutdown(socket.SHUT_RDWR)
    CLIENT.close()
    CLIENT = None
    
    #CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

######################################### SECURE SOCKET LAYER ########################################################

def generate_ssl_certificate(cert_file, key_file):
    # Create a new key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = "AvailData"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(1 * 24 * 60 * 60) #24 Hours 
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    
    # Save the certificate and private key to files
    with open(cert_file, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(key_file, "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    return(cert_file, key_file)

######################################### MAIN STARTUP SCRIPT #########################################################

load_dotenv()
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