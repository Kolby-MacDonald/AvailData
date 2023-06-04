import sys
import socket
import hashlib
import webbrowser
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

            #LOCALLY ENCRYPT THE DATA HERE

            #Encode and send the data
            CLIENT.send(username.encode())
            CLIENT.send(enc_password.encode())

            # Wait for a response.
            response = CLIENT.recv(1024).decode()

            # Response based functionality.
            # If somehow intercepted and bypassed by reverse engineering, the user access controll will prevent user data leaks.
            if response == "True": # If the server has the requested user in the specific table.
                self.open_user_page() # Open the main application window.
                print("Success")
                data_test = CLIENT.recv(1024).decode()
                print(data_test)
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

    # Function to send the user to the main application window.
    def open_user_page(self):
        userwindow = UserPage() # Define the users main application windows existence.
        widget.removeWidget(loginwindow) # Remove the login widget.
        widget.addWidget(userwindow) # Add the users main application window.

# The main application window where users will interact with their priveledge data.
class UserPage(QDialog):

    # Initialize the attributes of the userpage parent class.
    def __init__(self):
        super(UserPage, self).__init__()
        loadUi(r'Client\pages\user_page_test.ui', self) # Load the corresponding ui.




# Main Script:

# Pre application requirements
load_dotenv() # Load the environment variables.
CLIENT.connect((getenv("pub_Ip"), int(getenv("pub_port")))) # Connect to the client

# Application startup requirements and control.
app=QApplication(sys.argv)
widget=QtWidgets.QStackedWidget()
loginwindow = LoginPage() # Define the existance of the login application.
widget.addWidget(loginwindow)
widget.resize(1080,720)
widget.setMaximumWidth(1920)
widget.setMaximumHeight(1080)
widget.show()
app.exec_()