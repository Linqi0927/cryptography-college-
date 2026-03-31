
# 应用密码学 - RC4序列密码算法实现

# 1.密钥调度算法(KSA) - 兼容整数列表/字符串/bytes密钥
def ksa(key):
    # 统一处理密钥类型
    if isinstance(key, str):
        key = key.encode('utf-8')  # 字符串转bytes
    if isinstance(key, bytes):
        key = [byte for byte in key]  # bytes转整数列表
    key_length = len(key)  #统一编码处理
    S = list(range(256)) #初始化S盒：0-255填充
    j = 0
    for i in range (256): #S盒置换打乱
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

# 2.伪随机生成算法 （PRGA）
def prga(S, data_length):
    i = 0
    j = 0
    keystream = []
    S_copy = S.copy()  # 复制S盒
    # 循环次数匹配数据长度
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S_copy[i]) % 256
        S_copy[i], S_copy[j] = S_copy[j], S_copy[i]
        K = S_copy[(S_copy[i] + S_copy[j]) % 256]
        keystream.append(K)
    return keystream
    
# 3.数据加密与解密 
def encrypt(plaintext, key):
    # 处理明文类型：字符串→bytes→整数列表；直接整数列表则保留
    if isinstance(plaintext, str):
        plaintext = [byte for byte in plaintext.encode('utf-8')]
    elif isinstance(plaintext, bytes):
        plaintext = [byte for byte in plaintext]
    
    S = ksa(key)
    keystream = prga(S, len(plaintext))
    # 异或运算：整数列表间逐元素异或
    ciphertext = [p ^ k for p, k in zip(plaintext, keystream)]
    return ciphertext

def decrypt(ciphertext, key):

    return encrypt(ciphertext, key)

# ------------------- 测试示例 -------------------
if __name__ == '__main__':
    # 测试用例1：整数列表密钥+整数列表明文
    key = [0x01,0x02,0x03,0x04,0x05]
    plaintext = [0x00,0x01,0x02,0x03,0x04]
    
    print("="*50)
    print(f"初始密钥(十六进制): {[hex(k) for k in key]}")
    print(f"原始明文(十六进制): {[hex(p) for p in plaintext]}")
    print("="*50)
    
    # 加密
    ciphertext = encrypt(plaintext, key)
    print(f"加密后密文(十六进制): {[hex(c) for c in ciphertext]}")
    
    # 解密
    decrypt_text = decrypt(ciphertext, key)
    print(f"解密后明文(十六进制): {[hex(d) for d in decrypt_text]}")
    print("="*50)

    # 测试用例2：字符串密钥+字符串明文
    print("\n【扩展测试：字符串场景】")
    str_key = "crypto2026"
    str_plaintext = "24密科-RC4测试"
    # 字符串加密
    str_cipher = encrypt(str_plaintext, str_key)
    # 解密后转回字符串（整数列表→bytes→字符串）
    str_decrypt = bytes(decrypt(str_cipher, str_key)).decode('utf-8')
    print(f"字符串密钥: {str_key}")
    print(f"字符串明文: {str_plaintext}")
    print(f"加密后密文(十六进制): {[hex(c) for c in str_cipher]}")
    print(f"解密后字符串: {str_decrypt}")