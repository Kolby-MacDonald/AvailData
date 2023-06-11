import os
import json
import socket
import threading
import pandas as pd
import mysql.connector
from dotenv import load_dotenv


# Primary function controller.
def server_controller(server): 
    
    server.sendall("Connected".encode())
    username = server.recv(1024)
    password = server.recv(1024)
 
    db = mysql.connector.connect(
        host=os.getenv("db_host"), 
        user=os.getenv("db_user"), 
        password=os.getenv("db_pass"),
        database=os.getenv("db_name")
        )
    
    cursor = db.cursor()

    print(f"{username.decode()} is attempting access to the database.")

    cursor.execute(
        f'''SELECT * FROM {os.getenv("db_table_name")} where username = %s and password = %s''',
        (username.decode(), password.decode())
        )
    
    try:
        results = cursor.fetchone()
        user_name = results[1]
        user_table_access = results[3]
    except:
        pass

    if results:
        server.sendall("True".encode())
        print(f"{user_name} has accessed the database.")
        recieve_data(server, cursor, user_table_access)
    
    else:
        server.sendall("False".encode())
        print(f"{username.decode()} has failed to access the database.")

######################################## SERVER RESPONSE FUNCTIONS ###################################################

def send_data(server, data):
    json_data = json.dumps(data)
    data_length = len(json_data)
    header = f"{data_length:<{15}}".encode('utf-8')
    server.sendall(header + json_data.encode('utf-8'))

def recieve_data(server, cursor, user_table_access):
    while True:
        try:
            header = server.recv(15)
            if not header:
                break

            data_length = int(header.strip())
            data = server.recv(data_length).decode('utf-8')
            json_data = json.loads(data)
            request_type = json_data[0]

            if request_type == "get_init_data":
                user_table_names = init_data_response(server, cursor, user_table_access)
            
            elif request_type == "update_loaded_table":
                requested_table = json_data[1]
                result_select = int(json_data[2])
                update_loaded_table(server, cursor, user_table_names, requested_table, result_select)
        except:
            pass


######################################## DATA MANIPULATION FUNCTIONS ###################################################

def init_data_response(server, cursor, user_table_access):
    cursor.execute(f'''SHOW TABLES''')
    database_table_names_curse = cursor.fetchall()

    database_table_names = []
    user_table_names = []

    for tables in database_table_names_curse:
            database_table_names.append(tables[0])

    if user_table_access == "all":
        user_table_names = database_table_names

    elif type(user_table_access) == type(''):
        apparent_table_names = user_table_access.split(', ')
        for table_name in apparent_table_names:
            if table_name in database_table_names and table_name not in user_table_names:
                user_table_names.append(table_name)

    data = [user_table_names]
    send_data(server, data)
    return(user_table_names)

def update_loaded_table(server, cursor, user_table_names, requested_table, result_select):

    df_column_attributes = []
    column_names = []
    df = pd.DataFrame()

    if len(user_table_names) >= 1 and requested_table in user_table_names:
        cursor.execute(f'''SHOW COLUMNS FROM {requested_table}''')
        df_column_attributes = cursor.fetchall()
        for column in df_column_attributes:
            column_names.append(column[0])
        
        cursor.execute(f'''SELECT * FROM {requested_table} LIMIT {result_select}''')
        df = pd.DataFrame(cursor.fetchall(), columns=column_names)
        df = df.to_dict()

    data = [df]
    send_data(server, data)


######################################## START-UP SCRIPT ###################################################


# Load environment variables.
load_dotenv()

# Define and connect to server.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
server_socket.listen()
print("Server Online.")

while True:
    server, addr = server_socket.accept()
    print(f"incoming connection by: {addr}")
    threading.Thread(target=server_controller, args=(server,)).start()