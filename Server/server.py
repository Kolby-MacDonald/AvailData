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
        
        # Get all tables.
        cursor.execute(f'''SHOW TABLES''')
        database_table_names_curse = cursor.fetchall()
        database_table_names = []
        for i, tup in enumerate(database_table_names_curse):
                database_table_names.append(tup[0])

        if user_table_access == "all": # If the user has access to all tables - give them all table names.
            user_table_names = database_table_names

        elif type(user_table_access) == type(''): # If not, determine if their access tables actually tables exists.
            apparent_table_names = user_table_access.split(', ') # Split on predefined delimeter / Needs controller later.
            print(apparent_table_names)
            user_table_names = []
            for table_name in apparent_table_names: # Parse all actual table names
                if table_name in database_table_names:
                    user_table_names.append(table_name)

        
        try:
            cursor.execute(f'''SHOW COLUMNS FROM {user_table_names[0]}''')
            df_columns = str(cursor.fetchall())
            
            cursor.execute(f'''SELECT * FROM {user_table_names[0]}''')
            df = pd.DataFrame(cursor.fetchall()).astype(str)
        except:
            user_table_names = []
            df_columns = []
            df = pd.DataFrame().astype(str)

    #ENCRYPT DATA HERE

    #Wait for response after main window loads and send the init data.
        server.send(pickle.dumps(user_table_names)) # Send their access list to the Ui for user selection.
        server.send(pickle.dumps(df_columns)) # Send their access list to the Ui for user selection.
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