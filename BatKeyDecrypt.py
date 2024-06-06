import xxhash
import hashlib
import struct
import sqlite3
import os
import hmac
import Crypto.Cipher.AES as AES
import re
from xxhash import xxh32

def decrypt_sql_cipher(key:str,db_path,out_path):
    SQLITE_FILE_HEADER = b"SQLite format 3\x00"
    KEY_SIZE = 32
    DEFAULT_PAGESIZE = 4096
    DEFAULT_ITER = 64000
    if not os.path.exists(db_path) or not os.path.isfile(db_path):
        raise Exception("db_path must be a file")
    with open(db_path,"rb") as file:
        blist = file.read()

    salt = blist[:16]
    byteKey = hashlib.pbkdf2_hmac('sha1',key.encode(),salt,DEFAULT_ITER,dklen=KEY_SIZE)
    # 这里已经把盐值去掉
    first = blist[16:DEFAULT_PAGESIZE]
    if len(salt) != 16:
        raise Exception("salt must be 16 bytes")
    
    mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
    mac_key = hashlib.pbkdf2_hmac("sha1", byteKey, mac_salt, 2, KEY_SIZE)
    hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')

    if hash_mac.digest() != first[-32:-12]:
        print("password error!")
        return False

    block_sz = 16

    reserve_sz = 0
    # iv size
    iv_sz = 16
    # hmac size
    hmac_sz = 20

    reserve_sz = iv_sz
    reserve_sz += hmac_sz
    if reserve_sz % block_sz != 0:
        reserve_sz = ((reserve_sz // block_sz) + 1) * block_sz
    print("reserve_sz:",reserve_sz)

    salt_size = 16

    newblist = [blist[i:i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]

    with open(out_path,"wb") as deFile:
        # 第一页
        deFile.write(SQLITE_FILE_HEADER)
        pos1 = reserve_sz
        pos2 = pos1 - iv_sz
        iv = first[-pos1:-pos2]
        t = AES.new(byteKey, AES.MODE_CBC, iv)
        decrypted = t.decrypt(first[:-pos1])
        deFile.write(decrypted)
        deFile.write(first[-pos1:])

        # 后续页
        for i in newblist:
            pos = reserve_sz - iv_sz
            iv = i[-reserve_sz:-pos]
            t = AES.new(byteKey, AES.MODE_CBC, iv)
            decrypted = t.decrypt(i[:-reserve_sz])
            deFile.write(decrypted)
            deFile.write(i[-reserve_sz:])

    try:
        conn = sqlite3.connect(out_path)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        c.close()
        conn.close()
        return True
    except Exception as e:
        print("Error: ",e)
        return False
    
def get_db_key(account_id):
    db_name = f"BatChatSql{account_id}.db"
    
    try:
        user_id = int(account_id)
        # 构建字节数组
        b_temp = bytearray(8)
        b_temp[7] = user_id & 0xFF
        b_temp[6] = (user_id >> 8) & 0xFF
        b_temp[5] = (user_id >> 16) & 0xFF
        b_temp[4] = (user_id >> 24) & 0xFF
        b_temp[3] = (user_id >> 32) & 0xFF
        b_temp[2] = (user_id >> 40) & 0xFF
        b_temp[1] = (user_id >> 48) & 0xFF
        b_temp[0] = (user_id >> 56) & 0xFF
        
        mid_key = 0
        seed = -1756908916 & 0xFFFFFFFF  # 转换为无符号32位整数
        
        # 使用 xxhash 计算哈希
        xxhash = xxh32(seed=seed)
        xxhash.update(b_temp)
        
        mid_key = xxhash.intdigest() & 0xFFFFFFFF  # Get the unsigned 32-bit integer value
    
        temp_str = str(mid_key) + str(user_id)
        
        temp_str = f"{mid_key}{user_id}"
        
        # 使用 MD5 计算哈希
        md5_hash = hashlib.md5(temp_str.encode('utf-8')).hexdigest().upper()
        
        return md5_hash
    except Exception as ex:
        print(f"Error: {ex}")
        return None
    
def get_regex_digit(name):
    match = re.search(r'\d+', name)
    return match.group() if match else None


user_bat_id = "20141979"
key = get_db_key(user_bat_id)
decrypt_sql_cipher(key,"./BatChatSql20141979.db",'F:/Python/parser/test.db')
