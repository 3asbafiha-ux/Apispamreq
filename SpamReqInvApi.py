from flask import Flask, request, jsonify
from SpamReqInvApiMain import *
from SpamReqInvApiSetting import *
import threading
import time
import socket
import json
import base64
import requests
from datetime import datetime
import jwt
from google.protobuf.timestamp_pb2 import Timestamp
import errno
import select
app = Flask(__name__)
clients = {}
class TcpBotConnectMain:
    def __init__(self, account_id, password):
        self.account_id = account_id
        self.password = password
        self.key = None
        self.iv = None
        self.socket_client = None
        self.clientsocket = None
        self.running = False        
    def run(self):
        self.running = True
        while self.running:
            try:
                self.get_tok()
                break
            except Exception as e:
                print(f"Error in run: {e}. Retrying in 5 seconds...")
                time.sleep(5)    
    def stop(self):
        self.running = False
        if self.clientsocket:
            try:
                self.clientsocket.close()
            except:
                pass
        if self.socket_client:
            try:
                self.socket_client.close()
            except:
                pass    
    def restart(self, delay=5):
        print(f"[*] Restarting client {self.account_id} in {delay} seconds...")
        time.sleep(delay)
        self.run()    
    def is_socket_connected(self, sock):
        try:
            if sock is None:
                return False
            writable = select.select([], [sock], [], 0.1)[1]
            if sock in writable:
                sock.send(b'')
                return True
            return False
        except (OSError, socket.error) as e:
            if e.errno == errno.EBADF:
                print(f"[DEBUG] Socket bad file descriptor")
            return False
        except Exception as e:
            print(f"[DEBUG] Socket check error: {e}")
            return False    
    def ensure_connection(self):
        if not self.is_socket_connected(self.socket_client) and self.running:
            print(f"[RECONNECT] Attempting to reconnect account {self.account_id}")
            self.restart(delay=2)
            return False
        return True    
    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        while self.running:
            try:
                self.socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_client.settimeout(30)
                self.socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)                
                online_port = int(online_port)
                print(f"[ONLINE] Connecting to {online_ip}:{online_port}...")
                self.socket_client.connect((online_ip, online_port))
                print(f"[ONLINE] Connected to {online_ip}:{online_port}")
                self.socket_client.send(bytes.fromhex(tok))
                print(f"[ONLINE] Token sent successfully")
                while self.running and self.is_socket_connected(self.socket_client):
                    try:
                        readable, _, _ = select.select([self.socket_client], [], [], 1.0)
                        if self.socket_client in readable:
                            data2 = self.socket_client.recv(9999)
                            if not data2:
                                print("[ONLINE] Server closed connection gracefully")
                                break
                    except socket.timeout:
                        continue
                    except (OSError, socket.error) as e:
                        if e.errno == errno.EBADF:
                            print("[ONLINE] Bad file descriptor, reconnecting...")
                            break
                        else:
                            print(f"[ONLINE] Socket error: {e}. Reconnecting...")
                            break
                    except Exception as e:
                        print(f"[ONLINE] Unexpected error: {e}. Reconnecting...")
                        break                        
            except socket.timeout:
                print("[ONLINE] Connection timeout, retrying...")
            except (OSError, socket.error) as e:
                if e.errno == errno.EBADF:
                    print("[ONLINE] Bad file descriptor during connection")
                else:
                    print(f"[ONLINE] Connection error: {e}")
            except Exception as e:
                print(f"[ONLINE] Unexpected error: {e}")
            finally:
                if self.socket_client:
                    try:
                        self.socket_client.shutdown(socket.SHUT_RDWR)
                    except:
                        pass
                    try:
                        self.socket_client.close()
                    except:
                        pass
                    self.socket_client = None
                print("[ONLINE] Connection closed, waiting before reconnect...")
                time.sleep(3)   
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        while self.running:
            try:
                self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.clientsocket.settimeout(None)
                self.clientsocket.connect((whisper_ip, int(whisper_port)))
                print(f"[WHISPER] Connected to {whisper_ip}:{whisper_port}")
                self.clientsocket.send(bytes.fromhex(tok))        
                self.data = self.clientsocket.recv(1024)
                self.clientsocket.send(get_packet2(self.key, self.iv))

                thread = threading.Thread(
                    target=self.sockf1,
                    args=(tok, online_ip, online_port, "anything", key, iv)
                )
                thread.daemon = True
                thread.start()                
                while self.running:
                    dataS = self.clientsocket.recv(1024)
                    if not dataS:
                        break
            except Exception as e:
                print(f"[WHISPER] Error in connect: {e}. Retrying in 3 seconds...")
                time.sleep(3)
            finally:
                if self.clientsocket:
                    try:
                        self.clientsocket.close()
                    except:
                        pass
                time.sleep(2)  
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes() 
        MajorLogRes.ParseFromString(serialized_data)        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN    
    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now = str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex(Payload1A13)
        payload = payload.replace(b"2025-08-02 17:15:04", str(now).encode())
        payload = payload.replace(b"10e299be9f8199bd50f8c52bbae4695bc1935563ba17d3859c97237bd45cb428", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"b70245b92be827af56d8932346f351f2", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port    
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = GetLoginDataRegionMena
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': FreeFireVersion,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }        
        max_retries = 3
        attempt = 0
        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)            
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)
        print("Failed to get login data after multiple attempts.")
        return None, None, None, None    
    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": 'application/x-www-form-urlencoded',"Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "10e299be9f8199bd50f8c52bbae4695bc1935563ba17d3859c97237bd45cb428"
        OLD_OPEN_ID = "b70245b92be827af56d8932346f351f2"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        return data        
    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': FreeFireVersion,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex(Payload1A13)
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        hex_data = data.hex()
        encrypted_data = encrypt_api(hex_data)
        Final_Payload = bytes.fromhex(encrypted_data)
        URL = MajorLoginRegionMena
        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return (BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False    
    def get_tok(self):
        token_data = self.guest_token(self.account_id, self.password)
        if not token_data:
            print("Failed to get token")
            self.restart()
            return        
        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        print(whisper_ip, whisper_port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = self.dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            self.restart()
            return        
        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'
            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
        except Exception as e:
            print(f"Error creating final token: {e}")
            self.restart()
            return        
        self.connect(final_token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        return final_token, key, iv    
    def dec_to_hex(self, ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result   
    def execute_command(self, command, *args):
        if command == "reqinv":
            try:
                if not self.socket_client or not self.is_socket_connected(self.socket_client):
                    return "Socket not connected, please wait for connection..."
                client_id = 6701687488
                if args and len(args) > 0:
                    try:
                        client_id = int(args[0])
                    except ValueError:
                        print(f"[WARNING] Invalid client_id: {args[0]}, using default")               
                print(f"[COMMAND] Executing reqinv for account {self.account_id} to client {client_id}")
                commands_sent = 0
                for i in range(99999):
                    if not self.running or not self.is_socket_connected(self.socket_client):
                        break                    
                    try:
                        if i == 0: 
                            self.socket_client.send(OpenSquad(self.key, self.iv))
                            print(f"[COMMAND] OpenSquad sent")    
                        self.socket_client.send(ReqSquad(client_id, self.key, self.iv))
                        commands_sent += 1                        
                        if commands_sent % 10 == 0:
                            print(f"[COMMAND] Sent {commands_sent} requests for account {self.account_id} to client {client_id}")                        
                        time.sleep(0.1)
                    except (OSError, socket.error) as e:
                        if e.errno == errno.EBADF:
                            print(f"[ERROR] Bad file descriptor during send, reconnecting...")
                            self.restart()
                            return f"Socket error: {e}. Reconnecting..."
                        else:
                            print(f"[ERROR] Socket error during send: {e}")
                            break
                    except Exception as e:
                        print(f"[ERROR] Unexpected error during send: {e}")
                        break                
                return f"Command executed successfully, sent {commands_sent} requests to client {client_id}"                
            except Exception as e:
                print(f"[ERROR] in execute_command: {e}")
                return f"Error executing command: {e}"
        else:
            return f"Unknown command: {command}"
def load_accounts(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)
@app.route('/start_client', methods=['POST'])
def start_client():
    data = request.json
    account_id = data.get('account_id')
    password = data.get('password')    
    if not account_id or not password:
        return jsonify({'error': 'Account ID and password are required'}), 400    
    if account_id in clients:
        return jsonify({'error': 'Client already running'}), 400    
    client = TcpBotConnectMain(account_id, password)
    clients[account_id] = client    
    client_thread = threading.Thread(target=client.run)
    client_thread.daemon = True
    client_thread.start()    
    return jsonify({'message': f'Client {account_id} started successfully'}), 200
@app.route('/stop_client', methods=['POST'])
def stop_client():
    data = request.json
    account_id = data.get('account_id')    
    if not account_id:
        return jsonify({'error': 'Account ID is required'}), 400    
    if account_id not in clients:
        return jsonify({'error': 'Client not found'}), 404    
    client = clients[account_id]
    client.stop()
    del clients[account_id]    
    return jsonify({'message': f'Client {account_id} stopped successfully'}), 200
@app.route('/execute_command', methods=['POST'])
def execute_command():
    data = request.json
    account_id = data.get('account_id')
    command = data.get('command')
    client_id = data.get('client_id')
    if not account_id or not command:
        return jsonify({'error': 'Account ID and command are required'}), 400    
    if account_id not in clients:
        return jsonify({'error': 'Client not found'}), 404    
    client = clients[account_id]  
    args = []
    if client_id:
        try:
            args.append(int(client_id))
        except ValueError:
            return jsonify({'error': 'Invalid client_id format'}), 400    
    result = client.execute_command(command, *args)    
    return jsonify({'result': result}), 200
@app.route('/list_clients', methods=['GET'])
def list_clients():
    return jsonify({'clients': list(clients.keys())}), 200
if __name__ == "__main__":
    try:
        accounts = load_accounts('accounts.json')
        for account_id, password in accounts.items():
            client = TcpBotConnectMain(account_id, password)
            clients[account_id] = client
            client_thread = threading.Thread(target=client.run)
            client_thread.daemon = True
            client_thread.start()
            time.sleep(3)
    except FileNotFoundError:
        print("No accounts file found. Starting without preloaded accounts.")
    app.run(host='0.0.0.0', port=5000, debug=False)