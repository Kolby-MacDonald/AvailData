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

# Define our client.
CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Class to controll the login page functionality.
class LoginPage(QDialog):
    
    # Initialize the attributes of the login parent class.
    def __init__(self):
        super(LoginPage,self).__init__()
        loadUi(r'Client\pages\login_page.ui', self) # Load the login page UI after class is called.
        self.login_button.clicked.connect(self.login_function) # Define parameters for login buttons when clicked.
        self.signup_button.clicked.connect(self.open_signup_page) # Define parameters for signup page.
        self.linkedin_button.clicked.connect(self.open_linkedin) # Define parameters for linkedin button when clicked.


    # The user clicked the sign in button.
    def login_function(self):

        # Get required data.
        global CLIENT # Get our global Client definition.                     
        username = str(self.username_line_edit.text()) # Take the input username from the respective linedit.
        password = str(self.password_line_edit.text()) # Take the input password from the respective linedit.
        enc_password = hashlib.sha256(password.encode()).hexdigest() #SHA256 Hash the password before sending.
        
        # Clear the linedit fields.
        self.username_line_edit.setText("")
        self.password_line_edit.setText("")

        # Send the data to the server and wait for a response.
        if username != "" and password !="":
            CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port")))) # Connect to the client
            connected = CLIENT.recv(1024).decode()
            # ENCRYPT DATA HERE
            
            if connected == "Connected":
            # Encode and send the data
                CLIENT.sendall(username.encode())
                CLIENT.sendall(enc_password.encode())

            # Wait for a response.
            response = CLIENT.recv(1024).decode()

            # Response based functionality.
            if response == "True": # If the server has the requested user in the specific table.
                self.open_user_page() # Open the main application window.

            else: # If the server does not have the requested data.
                CLIENT.shutdown(socket.SHUT_RDWR) # Restart the socket.
                CLIENT.close()
                CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port"))))
                print("Failed")
        else:
            print("Verification failed! (Local)")

    # Function to open the users web browser to creators LinkedIn.
    def open_linkedin(self):
        webbrowser.open('www.linkedin.com/in/kolby-macdonald')

    # Function to open the signup page (currently inactive)
    def open_signup_page(self):
        widget.removeWidget(login_window) # Remove the login widget.
        widget.addWidget(signup_window) # Add the users signup application window.

    # Function to send the user to the main application window.
    def open_user_page(self):
        user_window = UserPage() # Define the users main application windows existence.
        widget.removeWidget(login_window) # Remove the login widget.
        widget.addWidget(user_window) # Add the users main application window.

########################################################################################################################

# The signup class - currently unimplented for actual signup.
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
        widget.removeWidget(signup_window) # Remove the login widget.
        widget.addWidget(login_window) # Add the users main application window.

########################################################################################################################

# The main application window where users will interact with their priveledge data.
class UserPage(QDialog):

    # Initialize the attributes of the userpage parent class.
    def __init__(self):
        super(UserPage, self).__init__()
        loadUi(r'Client\pages\user_page_test.ui', self) # Load the corresponding ui.
        self.table_select_combobox.currentTextChanged.connect(self.update_table_view)
        self.result_select_combobox.currentTextChanged.connect(self.update_table_view)
        self.loaded_table_edit

        UserPage.request_handler(self, "get_init_data")      

        # Client side request handler must be external, data is called on a by necessity basic.
    def send_data(self, data):
        json_data = json.dumps(data) # Convert the data to JSON format
        data_length = len(json_data) # Get the length of the JSON data
        header = f"{data_length:<{15}}".encode('utf-8') # Create a fixed-length header indicating the data length

        CLIENT.sendall(header + json_data.encode('utf-8'))

    def request_handler(self, request):
        if request == "get_init_data":
            data = [request]
            UserPage.send_data(self, data)
            UserPage.recieve_data(self, request)

        elif request == "update_loaded_table":
            # Request Type, Table Name, Number of Results to Return
            data = [request, self.table_select_combobox.currentText(), self.result_select_combobox.currentText()]
            UserPage.send_data(self, data)
            UserPage.recieve_data(self, request)


    def recieve_data(self, request):
        try:
            header = CLIENT.recv(15)
            if not header:
                return None

            # Extract the data length from the header
            data_length = int(header.strip())

            # Receive the data using the extracted data length
            data = CLIENT.recv(data_length).decode('utf-8')

            # Parse the JSON data
            json_data = json.loads(data)

            #print(json_data)
            
            if request == "get_init_data":
                UserPage.get_init_data(self, json_data)

            elif request == "update_table_view":
                UserPage.update_table_view(self, json_data)

        except:
            pass

    def get_init_data(self, init_data):
        user_table_names = init_data[0]
        init_table_data = init_data[1]

        if user_table_names != []:
            self.table_select_combobox.addItems(user_table_names)

            df = pd.DataFrame.from_dict(init_table_data)
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
            pass

    def update_table_view(self, update_data):
        #request_handler("update_loaded_table")
        print("Update table view requested")
        if update_data != []:
            
            pass
        pass


########################################################################################################################

# Pre application requirements
load_dotenv() # Load the environment variables.


# Application startup requirements and control.
app=QApplication(sys.argv)
widget=QtWidgets.QStackedWidget()
login_window = LoginPage() # Define the existance of the login application.
signup_window = SignUpPage() # Define the existance of the signup application.
widget.addWidget(login_window)
widget.resize(1080,720)
widget.setMaximumWidth(1920)
widget.setMaximumHeight(1080)
widget.show()
app.exec_()