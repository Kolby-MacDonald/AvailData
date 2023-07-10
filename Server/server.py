import os
import ssl
import json
import socket
import threading
import pandas as pd
import mysql.connector
from OpenSSL import crypto
from dotenv import load_dotenv

ACTIVE_THREADS = {}
TOTAL_CONNECTIONS = 0

# Primary function controller.
def server_controller(client_sock, conn_ip, conn_num, firewall_mode, thread_id, terminate_event):


    db = mysql.connector.connect(
        host=os.getenv("db_host"), 
        user=os.getenv("db_user"), 
        password=os.getenv("db_pass"),
        database=os.getenv("db_name")
        )
    cursor = db.cursor()
    
    #FIREWALL: TEST CONNECTION IF ENABLED
    if str(os.getenv("firewall_enabled")) == "True" and str(os.getenv("firewall_enabled")):
        cursor.execute(
            f'''SELECT * FROM {os.getenv("db_firewall_name")} WHERE %s = %s''', 
            ((str(os.getenv("firewall_mode")).lower(),conn_ip)))
        
        try:
            ip_result = cursor.fetchone()
            ip_result = ip_result[0]
        except: pass

        if (firewall_mode == "blacklist" and ip_result) or (firewall_mode == "whitelist" and ip_result == False):
            close_connection(client_sock, conn_num, thread_id)
    
    credentials = receive_data(client_sock, conn_num, thread_id, None, None, None, None)

    cursor.execute(
        f'''SELECT * FROM {os.getenv("db_table_name")} WHERE username = %s AND password = %s''',
        (str(credentials[1]), str(credentials[2]))
        )
    
    try:
        results = cursor.fetchone()
        user_db_id = results[0]
        employee_name = results[1]
        job_title = results[2] 
        db_role = results[3]
        username = results[4]
        user_write_table_access = results[7]
        user_read_table_access = results[8]
    except: pass

    if results:
        send_data(client_sock, True)
        print(f"{user_db_id} | {employee_name}:{username} | {job_title}:{db_role} | has accessed the database.")
        receive_data(client_sock, conn_num, thread_id, cursor, db_role, user_write_table_access, user_read_table_access)
    
    else:
        client_sock.sendall("False".encode())
        print(f"{conn_ip} Failed To Connect | Username Given: {str(credentials[1])}")
        db.close()
        close_connection(client_sock, conn_num, thread_id)

######################################## SERVER RESPONSE FUNCTIONS ###################################################

def send_data(client_sock, data):
    json_data = json.dumps(data)
    data_length = len(json_data)
    header = f"{data_length:<{15}}".encode('utf-8')
    client_sock.sendall(header + json_data.encode('utf-8'))

def receive_data(client_sock, conn_num, thread_id, cursor, db_role, user_write_table_access, user_read_table_access):
    while True:
        try:
            header = client_sock.recv(15)
            if not header:
                break

            data_length = int(header.strip())
            data = client_sock.recv(data_length).decode('utf-8')
            json_data = json.loads(data)
            request_type = json_data[0]

            if request_type == "login":
                return(json_data)
            
            elif request_type == "get_init_data":
                user_table_names = init_data_response(client_sock, cursor, db_role, user_write_table_access, user_read_table_access)
                user_write_table_names = user_table_names[0]
                user_read_table_names = user_table_names[1]
            
            elif request_type == "update_loaded_table":
                requested_table = json_data[1]
                result_select = int(json_data[2])
                update_loaded_table(client_sock, cursor, user_write_table_names, user_read_table_names, requested_table, result_select)

            elif request_type == "log_out":
                close_connection(client_sock, conn_num,thread_id)
        except: pass


######################################## DATA MANIPULATION FUNCTIONS ###################################################

def init_data_response(client_sock, cursor, db_role, user_write_table_access, user_read_table_access):
    cursor.execute(f'''SHOW TABLES''')
    database_table_names_curse = cursor.fetchall()

    database_table_names = []
    user_write_table_names = []
    user_read_table_names = []

    for tables in database_table_names_curse:
            database_table_names.append(tables[0])

    #Write control-------------------------------------------------------------------------------

    if user_write_table_access == "all" or db_role == "admin" :
        user_write_table_names = database_table_names

    elif type(user_write_table_access) == type(''):
        apparent_table_names = user_write_table_access.split(', ')
        for table_name in apparent_table_names:
            if table_name in database_table_names and table_name not in user_write_table_names:
                user_write_table_names.append(str(table_name))

    #Read Control---------------------------------------------------------------------------
    
    if user_read_table_access == "all" and db_role != "admin":
        user_read_table_access == database_table_names

    elif type(user_read_table_access) == type(''):
        apparent_table_names = user_read_table_access.split(', ')
        for table_name in apparent_table_names:
            if table_name in database_table_names and table_name not in user_read_table_names and table_name not in user_write_table_names:
                user_read_table_names.append(str(table_name))

    data = [user_write_table_names, user_read_table_names]
    send_data(client_sock,data)

    return(user_write_table_names, user_read_table_names)

def update_loaded_table(client_sock, cursor, user_write_table_names, user_read_table_names, requested_table, result_select):

    df_column_attributes = []
    column_names = []
    df = pd.DataFrame()

    user_table_names = user_read_table_names + user_write_table_names

    if len(user_table_names) >= 1 and requested_table in user_table_names:
        cursor.execute(f'''SHOW COLUMNS FROM {requested_table}''')
        df_column_attributes = cursor.fetchall()
        for column in df_column_attributes:
            column_names.append(column[0])
        
        cursor.execute(f'''SELECT * FROM {requested_table} LIMIT {result_select}''')
        df = pd.DataFrame(cursor.fetchall(), columns=column_names)
        df = df.to_dict()

    data = [df]
    send_data(client_sock, data)

######################################## SOCKET SECURITY LAYER #######################################################
def generate_ssl_certificate(cert_file, key_file):
    # Create a new key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed certificate
    cert = crypto.X509()
    cert.get_subject().CN = "AvailData"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    
    # Save the certificate and private key to files
    with open(cert_file, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open(key_file, "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    return(cert_file, key_file)

def close_connection(client_sock, conn_num, thread_id):
    global ACTIVE_THREADS
    client_sock.shutdown(socket.SHUT_RDWR)
    client_sock.close()

    #To terminate a specific thread:
    terminate_event = threading.Event()
    print(f"Closing Connection: {conn_num}")
    terminate_event = ACTIVE_THREADS[thread_id]["event"]
    del ACTIVE_THREADS[thread_id]
    terminate_event.set()

######################################## START-UP SCRIPT ###################################################

def main():
    global TOTAL_CONNECTIONS
    load_dotenv()


    # WRAP SOCKET IN SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    if str(os.getenv("ca_cert_required")) == "True":
        cert_file = str(os.getenv("ca_cert_file"))
        key_file =  str(os.getenv("ca_key_file"))
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.load_verify_locations(str(os.getenv("ca_verify_file")))
    else:
        cert_file = str(os.getenv("gen_cert_file"))
        key_file =  str(os.getenv("gen_key_file"))
        generate_ssl_certificate(cert_file, key_file)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.verify_mode = ssl.CERT_NONE

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
    ssl_server_socket = context.wrap_socket(server_socket, server_side=True)
    ssl_server_socket.listen()

    # GAURENTEE FIREWALL IS SET PROPERLY
    print("Server Online.")
    firewall_mode = str(os.getenv("firewall_mode")).lower()
    if firewall_mode not in ["whitelist", "blacklist"]:
        print('Firewall Enabled With No Mode... Setting to "blacklist" Mode')
        firewall_mode = "blacklist"
    print(f"Firewall Enabled | Mode: {firewall_mode}")

    while True:
        client_sock, addr = ssl_server_socket.accept()
        print(f"incoming connection by: {addr}")

        thread_id = len(ACTIVE_THREADS) + 1
        terminate_event = threading.Event()

        TOTAL_CONNECTIONS += 1
        conn_num = TOTAL_CONNECTIONS
        thread = threading.Thread(target=server_controller, args=(client_sock, addr[0], conn_num, firewall_mode, thread_id, terminate_event,))
        ACTIVE_THREADS[thread_id] = {"thread": thread, "event": terminate_event}
        thread.start()
        print(f'''Active Clients ({len(ACTIVE_THREADS)}) | Closed Clients ({TOTAL_CONNECTIONS - len(ACTIVE_THREADS)}) | Total: ({TOTAL_CONNECTIONS}).''')

if __name__ == "__main__":
    main()