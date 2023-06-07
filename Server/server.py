import os
import socket
import pickle
import threading
import pandas as pd
import mysql.connector
from dotenv import load_dotenv


# Primary function controller.
def server_controller(server): 
    
    # The very first recieved data will always be username and password.
    username = server.recv(1024)
    password = server.recv(1024)

    # Once a login attempt is recieved, connect to the database.
    # The data is stored in environment variables for security. 
    db = mysql.connector.connect(
        host=os.getenv("db_host"), 
        user=os.getenv("db_user"), 
        password=os.getenv("db_pass"),
        database=os.getenv("db_name")
        )
    
    # Define the database cursor.
    cursor = db.cursor()

    print(f"{username.decode()} is attempting access to the database.") # Log the attempt (debugging purposes)

    # Attempt to find the user info in the database
    # Later passwords (and potentially usernames) will need to become unique to prevent overlaps. 
    cursor.execute(
        f'''SELECT * FROM {os.getenv("db_table_name")} where username = %s and password = %s''',
        (username.decode(), password.decode())
        )
    
    # Try to pull the cursor results of the login request and organize them locally.
    try:
        results = cursor.fetchone()
        #user_id = results[0] # Currently not needed, potentially needed later.
        user_name = results[1]
        #user_pass = results[2] # Currently not needed, potentially needed later.
        user_table_access = results[3]
    except:
        pass

    if results:  # If those results exist, then log the user in.
        server.send("True".encode())
        print(f"{user_name} has accessed the database.") # Log the access (debugging purposes).
        init_data_response(server, cursor, user_table_access) # Initialize data for main page start-up.
        # main_data_controller()
    
    else: # If those results don't exist, then tell the client it failed.
        server.send("False".encode())
        print(f"{username.decode()} has failed to access the database.") # Log the failed attempt (debugging purposes).

    
# Initialize for main page start-up
def init_data_response(server, cursor, user_table_access):
    
    if server.recv(1024).decode() == "get_init_data":

        cursor.execute(f'''SHOW TABLES''')
        database_table_names_curse = cursor.fetchall()

        database_table_names = [] # Names of all tables in database
        user_table_names = [] # Names of tables the user has access to
        df_column_attributes = [] # Attributes of the table columns the user has access to
        column_names = [] # Column names to append to dataframe
        df = pd.DataFrame() # Empty dataframe to send if one not found.

        for i, tup in enumerate(database_table_names_curse):
                database_table_names.append(tup[0])

        if user_table_access == "all":
            user_table_names = database_table_names

        elif type(user_table_access) == type(''):
            apparent_table_names = user_table_access.split(', ')
            for table_name in apparent_table_names:
                if table_name in database_table_names and table_name not in user_table_names:
                    user_table_names.append(table_name)

        if len(user_table_names) >= 1:
            cursor.execute(f'''SHOW COLUMNS FROM {os.getenv("db_table_name")}''')
            df_column_attributes = cursor.fetchall()
            for column in df_column_attributes:
                column_names.append(column[0])
            
            cursor.execute(f'''SELECT * FROM {os.getenv("db_table_name")} LIMIT 100''')
            df = pd.DataFrame(cursor.fetchall(), columns=column_names)

    #ENCRYPT DATA HERE

    #Wait for response after main window loads and send the init data.
        server.send(pickle.dumps(user_table_names))
        server.send(pickle.dumps(df))

def main_data_controller():
    while True:
        
        pass
    pass
  

def main():

    # Load environment variables.
    load_dotenv()

    # Define and connect to server.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
    server_socket.listen()
    print("Server listening.") # Log the server start (debugging purposes).

    # Accept incoming connection and create a thread to handle them.
    while True:
        server, addr = server_socket.accept()
        print(f"incoming connection by: {addr}") # Log the incoming IP (debugging purposes).
        threading.Thread(target=server_controller, args=(server,)).start()

main()