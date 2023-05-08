#设计一个保存账号密码的程序

#导入sqlite3模块
import hashlib
import pickle
import sqlite3
from tkinter import messagebox
import tkinter as tk
#导入cryptography模块
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
#导入tkinter模块
from tkinter import *

import pyperclip


class Password:
    #初始化
    def __init__(self,fernet_key,aes_key,aes_iv):
        self.fernet_key = fernet_key
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        # 创建Fernet对象
        global fernet_cipher
        fernet_cipher = Fernet(self.fernet_key)
        # 创建AES对象
        global aes_cipher
        aes_cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv), backend=default_backend())
        #创建数据库
        conn = sqlite3.connect('password.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS password ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, password TEXT NOT NULL )''')
        conn.commit()
        c.close()
        conn.close()
        #创建窗口
        self.root = Tk()


    #定义函数，实现向数据库中添加条目
    def add(self):
        #获取输入框中的内容
        name = entry_name.get()
        password = entry_password.get()
        #判断输入框是否为空
        if name == '' or password == '':
            #弹出提示框
            messagebox.showinfo('提示', '账号或密码不能为空！')
        else:
            #加密数据
            password = self.encrypt_data(password)
            #插入数据
            conn = sqlite3.connect('password.db')
            c = conn.cursor()
            c.execute("INSERT INTO password (name, password) VALUES (?, ?)", (name, password))
            conn.commit()
            c.close()
            #弹出提示框
            messagebox.showinfo('提示', '添加成功！')
            #清空输入框
            entry_name.delete(0, END)
            entry_password.delete(0, END)

    #定义函数,显示所有条目的name和id
    def show(self):
        #获取数据库中的数据
        conn = sqlite3.connect('password.db')
        c = conn.cursor()
        c.execute("SELECT id, name FROM password")
        result = c.fetchall()
        conn.commit()
        c.close()
        #显示在列表框中
        listbox.delete(0, END)
        for item in result:
            listbox.insert(END, item)
        return result
    
    #定义函数，实现删除功能
    def delete(self):
        #获取列表框中选中的数据
        select = listbox.get(listbox.curselection())
        #获取选中数据的id
        id = select[0]
        #删除数据
        conn = sqlite3.connect('password.db')
        c = conn.cursor()
        c.execute("DELETE FROM password WHERE id = ?", (id,))
        conn.commit()
        c.close()
        #弹出提示框
        messagebox.showinfo('提示', '删除成功！')

    #定义函数，实现基本的UI界面
    def ui(self):
        #设置窗口标题
        self.root.title('密码管理器')
        #设置窗口大小
        self.root.geometry('600x800')
        #设置窗口位置
        self.root.geometry('+500+200')
        #设置窗口图标
        #root.iconbitmap('icon.ico')
        #设置窗口大小是否可变
        self.root.resizable(width=True, height=True)
        #创建标签
        label_name = Label(self.root, text='账号：')
        label_password = Label(self.root, text='密码：')
        #创建输入框
        global entry_name
        entry_name = Entry(self.root)
        global entry_password
        entry_password = Entry(self.root)
        #创建按钮
        button_add = Button(self.root, text='添加', command=self.add)
        #创建显示按钮
        button_show = Button(self.root, text='显示条目', command=self.show)
        #创建显示密码按钮
        button_show_password = Button(self.root, text='显示密码', command=self.show_password)
        #创建删除按钮
        button_delete = Button(self.root, text='删除', command=self.delete)
        #创建列表框
        global listbox
        listbox = Listbox(self.root)
        #创建滚动条
        scrollbar = Scrollbar(self.root)
        #将滚动条与列表框关联
        scrollbar.config(command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)

        #设置各个元素的位置
        label_name.grid(row=0, column=0, padx=10, pady=10)
        label_password.grid(row=1, column=0, padx=10, pady=10)
        entry_name.grid(row=0, column=1, padx=10, pady=10)
        entry_password.grid(row=1, column=1, padx=10, pady=10)
        button_add.grid(row=2, column=1, padx=10, pady=10)
        listbox.grid(row=0, column=2, rowspan=3, padx=10, pady=10)
        scrollbar.grid(row=0, column=3, rowspan=3, padx=10, pady=10)
        button_show.grid(row=3, column=2, padx=10, pady=10)
        button_delete.grid(row=3, column=3, padx=10, pady=10)
        button_show_password.grid(row=3, column=4, padx=10, pady=10)
        #进入消息循环
        self.root.mainloop()
    
    #加密函数
    def encrypt_data(self, data):
        # 使用Fernet加密数据
        encrypted_data = fernet_cipher.encrypt(data.encode())

        # 使用AES加密数据
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(encrypted_data) + padder.finalize()
        encryptor = aes_cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data
    
    #解密函数
    def decrypt_data(self, data):
        # 使用AES解密数据
        decryptor = aes_cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # 使用Fernet解密数据
        decrypted_data = fernet_cipher.decrypt(unpadded_data).decode()

        return decrypted_data
    
    #定义函数，实现查看密码功能
    def show_password(self):
        #获取列表框中选中的数据
        select = listbox.get(listbox.curselection())
        #获取选中数据的id
        id = select[0]
        #获取选中数据的name
        name = select[1]
        #获取数据库中的数据
        conn = sqlite3.connect('password.db')
        c = conn.cursor()
        c.execute("SELECT password FROM password WHERE id = ?", (id,))
        result = c.fetchone()
        conn.commit()
        c.close()
        #解密数据
        password = self.decrypt_data(result[0])
        #弹出提示框
        messagebox.showinfo('提示', '账号：' + name + '\n' + '密码：' + password)
        #密码复制到剪切板
        pyperclip.copy(password)

    #当点击显示密码的时候验证身份
    def log(self):
        window = tk.Toplevel(self.root)
        
    
#定义函数，实现登录窗口
def log_window():
    global log_box
    log_box = Tk()
    log_box.title('登录')
    log_box.geometry('300x100')
    log_box.geometry('+500+200')
    log_box.resizable(width=False, height=False)
    label_passwd = Label(log_box, text='密码：')
    global entry_passwd
    entry_passwd = Entry(log_box, show='*')
    button_log = Button(log_box, text='登录', command=check_passwd)
    label_passwd.grid(row=0, column=0, padx=10, pady=10)
    entry_passwd.grid(row=0, column=1, padx=10, pady=10)
    button_log.grid(row=1, column=1, padx=10, pady=10)
    log_box.mainloop()



#定义函数，验证密码
def check_passwd():
    hash = hashlib.md5()
    hash.update(entry_passwd.get().encode())
    #连接user.db数据库,从user表中获取密码
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute("SELECT password FROM user WHERE id = 1")
    result = c.fetchone()
    conn.commit()
    c.close()
    #获取数据库中的密码
    password = result[0]
    #判断密码是否正确
    if hash.hexdigest() == password:
        messagebox.showinfo('提示', '登录成功')
        #关闭登录窗口
        log_box.destroy()
        #连接user.db数据库,从key表中获取密钥
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        c.execute("SELECT fernet_key, aes_key, aes_iv FROM key WHERE id = 1")
        result = c.fetchone()
        conn.commit()
        c.close()
        #获取密钥
        fernet_key = result[0]
        aes_key = result[1]
        aes_iv = result[2]
        password = Password(fernet_key, aes_key, aes_iv)
        #调用函数，实现基本的UI界面
        password.ui()
    else:
        messagebox.showerror('错误', '密码错误')
    

#主函数
if __name__ == '__main__':
    log_window()

    