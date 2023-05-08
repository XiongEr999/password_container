import pickle
from tkinter import messagebox
from cryptography.fernet import Fernet
import os
import sqlite3
import tkinter as tk
from tkinter import *
import hashlib

# 生成Fernet密钥
def generate_key():
    fernet_key = Fernet.generate_key()
    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)
    #将密钥存在user.db中另外一个表中
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS key ( id INTEGER PRIMARY KEY AUTOINCREMENT, fernet_key TEXT NOT NULL, aes_key TEXT NOT NULL, aes_iv TEXT NOT NULL )''')
    c.execute("INSERT INTO key (fernet_key, aes_key, aes_iv) VALUES (?, ?, ?)", (fernet_key, aes_key, aes_iv))
    conn.commit()
    c.close()
    conn.close()

#定义函数，向数据库中添加密码
def ini_table():
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS user ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, password TEXT NOT NULL )''')
    #弹出提示框，要求输入密码，并获取密码，加密后存入数据库
    passwd = input('请输入密码：')
    hash = hashlib.md5()
    hash.update(passwd.encode(encoding='utf-8'))
    passwd = hash.hexdigest()
    c.execute("INSERT INTO user (name, password) VALUES (?, ?)", ('admin', passwd))
    conn.commit()
    c.close()
    conn.close()

#定义函数，判断user中是否有密码
def is_passwd():
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute("SELECT password FROM user WHERE id = 1")
    password = c.fetchone()
    c.close()
    conn.close()
    if password == None:
        return False
    else:
        return True
    #关闭数据库

#主函数
if __name__ == '__main__':
    #执行is_passwd函数,如果报错，说明user.db中没有user表，需要初始化
    try:
        is_passwd()
    except:
        #初始化数据库
        ini_table()
    #判断user.db中是否有密码
    if is_passwd():
        messagebox.showinfo('提示', '只能运行一次！')
    else:
        #如果没有密码，就执行初始化函数
        ini_table()
        #生成Fernet密钥
        generate_key()


