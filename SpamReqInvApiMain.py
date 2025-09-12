import os
import sys
import re
import json
import time
import socket
import random
import logging
import binascii
import threading
from datetime import datetime
from time import sleep
import requests
import httpx
import urllib3
import jwt
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import google.protobuf
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToJson
from protobuf_decoder.protobuf_decoder import Parser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
secertsq = None
from SpamReqInvApiSetting import *
def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)
    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
def encode_varint(num):
    if num < 0: raise ValueError("Number must be non-negative")
    out = []
    while True:
        b = num & 0x7F
        num >>= 7
        if num: b |= 0x80
        out.append(b)
        if not num: break
    return bytes(out)
def create_field(num, val):
    if isinstance(val, int): 
        return encode_varint((num<<3)|0) + encode_varint(val)
    if isinstance(val, (str,bytes)):
        v = val.encode() if isinstance(val,str) else val
        return encode_varint((num<<3)|2) + encode_varint(len(v)) + v
    if isinstance(val, dict):
        nested = create_packet(val)
        return encode_varint((num<<3)|2) + encode_varint(len(nested)) + nested
    return b""
def create_packet(fields):
    return b"".join(create_field(k,v) for k,v in fields.items())
def dec_to_hex(n): 
    return f"{n:02x}"
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
def aes_encrypt(data, key, iv):
    data = bytes.fromhex(data) if isinstance(data,str) else data
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data,16)).hex()
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
def get_packet2(key,iv): 
    fields = {1:3, 2:{2:5,3:"en"}}
    packet = create_packet(fields).hex()+"7200"
    hlen = len(aes_encrypt(packet,key,iv))//2
    return bytes.fromhex("1215000000"+dec_to_hex(hlen)+aes_encrypt(packet,key,iv))
def OpenSquad(key, iv):
    fields = {1:1, 2:{2:"\u0001",3:1,4:1,5:"en",9:1,11:1,13:1,14:{2:5756,6:11,8:"1.109.5",9:3,10:2}}}
    packet = create_packet(fields).hex()
    encrypted_packet = aes_encrypt(packet, key, iv)
    hlen = len(encrypted_packet) // 2
    return bytes.fromhex("0515000000" + dec_to_hex(hlen) + encrypted_packet)
def ReqSquad(client_id, key, iv):
    fields = {1:2, 2:{1:int(client_id),2:"ME",4:1}}
    packet = create_packet(fields).hex()
    encrypted_packet = aes_encrypt(packet, key, iv)
    hlen = len(encrypted_packet) // 2
    return bytes.fromhex("0515000000" + dec_to_hex(hlen) + encrypted_packet)
def GeneratMsg(msg, cid, key, iv):
    fields = {1:1,2:{1:7141867918,2:int(cid),3:2,4:msg,5:int(datetime.now().timestamp()),7:2,9:{1:"TheIconicDevFOx",2:902000066,3:901037021,4:random.randint(301,330),5:901037021,8:"TheIconicDevFOx",10:2,11:2010,13:{1:2,2:1},14:{1:11017917409,2:8,3:"\u0010\u0015\b\n\u000b"}},10:"en",13:{1:"https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",2:1,3:1},14:{1:{1:random.choice([1,4]),2:1,3:random.randint(1,180),4:1,5:int(datetime.now().timestamp()),6:"en"}}}}
    packet = create_packet(fields).hex()
    encrypted_packet = aes_encrypt(packet, key, iv)
    hlen = len(encrypted_packet) // 2
    hlen_final = dec_to_hex(hlen)
    if len(hlen_final) == 2:
        final_packet = "1215000000" + hlen_final + encrypted_packet
    elif len(hlen_final) == 3:
        final_packet = "121500000" + hlen_final + encrypted_packet
    elif len(hlen_final) == 4:
        final_packet = "12150000" + hlen_final + encrypted_packet
    elif len(hlen_final) == 5:
        final_packet = "1215000" + hlen_final + encrypted_packet
    return bytes.fromhex(final_packet)