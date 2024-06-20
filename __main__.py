import hashlib
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import base64
import secrets
import string
import re
import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AesGui:
    """aes Window"""

    def __init__(self, master=None):
        self.root = ttk.Frame(master)

        label2 = ttk.Label(self.root, text="Key:")
        label2.grid(row=0, column=0, sticky="e")
        self.entry2 = ttk.Entry(self.root)
        self.entry2.grid(row=0, column=1, sticky="w")

        label7 = ttk.Label(self.root, text="IV:")
        label7.grid(row=1, column=0, sticky="e")
        self.entry3 = ttk.Entry(self.root)
        self.entry3.grid(row=1, column=1, sticky="w")

        label3 = ttk.Label(self.root, text="Encryption mode:")
        label3.grid(row=2, column=0, sticky="e")
        self.mode_box = ttk.Combobox(self.root, values=("ECB", "CBC"))
        self.mode_box.current(0)
        self.mode_box.grid(row=2, column=1, sticky="w")

        label4 = ttk.Label(self.root, text="Padding mode:")
        label4.grid(row=3, column=0, sticky="e")
        self.padding_box = ttk.Combobox(
            self.root, values=("nopadding", "pkcs7", "iso7816", "x923")
        )
        self.padding_box.current(0)
        self.padding_box.grid(row=3, column=1, sticky="w")

        label5 = ttk.Label(self.root, text="Block length:")
        label5.grid(row=4, column=0, sticky="e")
        self.blocksize_box = ttk.Combobox(self.root, values=("128", "192", "256"))
        self.blocksize_box.current(0)
        self.blocksize_box.grid(row=4, column=1, sticky="w")

        # 创建输入框和标签
        label1 = ttk.LabelFrame(self.root, text="Input:")
        label1.grid(row=5, column=0, columnspan=2)
        self.entry1 = ScrolledText(label1, width=50, height=10)
        self.entry1.pack()

        # 创建加密和解密按钮
        encrypt_button = ttk.Button(self.root, text="Encrypt", command=self.encrypt)
        encrypt_button.grid(row=6, column=0)

        decrypt_button = ttk.Button(self.root, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=6, column=1)

        # 创建输出框和标签
        label6 = ttk.LabelFrame(self.root, text="Output:")
        label6.grid(row=7, column=0, columnspan=2)
        self.text = ScrolledText(label6, width=50, height=10)
        self.text.pack()

    # 加密函数
    def encrypt(self):
        try:
            # 获取输入框中的明文和密钥
            plaintext = self.entry1.get("1.0", "end")
            key = self.entry2.get()
            iv = self.entry3.get()
            mode = self.mode_box.get()
            padding = self.padding_box.get()
            blocksize = self.blocksize_box.get()
            plaintext = plaintext.encode()
            blocksize = int(blocksize)

            # 将密钥填充到指定长度
            if len(key) < blocksize / 8:
                messagebox.showerror(
                    "Error",
                    f"The password must contain at least {blocksize / 8} characters.",
                )
                return

            key = key.encode()

            # 根据选择的加密模式和填充方式创建AES对象
            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
            elif mode == "CBC":
                if len(iv) < 16:
                    messagebox.showerror("Error", "The offset length must be 16 bits")
                    return

                iv = iv.encode()
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            # 将明文填充到指定长度
            if padding == "pkcs7":
                plaintext = pad(plaintext, AES.block_size)
            elif padding == "iso7816":
                plaintext = pad(plaintext, AES.block_size, "iso7816")
            elif padding == "x923":
                plaintext = pad(plaintext, AES.block_size, "x923")

            # 加密明文并将结果转换为base64格式
            ciphertext = cipher.encrypt(plaintext)
            ciphertext = base64.b64encode(ciphertext).decode()

            # 显示加密结果
            self.text.delete(1.0, "end")
            self.text.insert("end", ciphertext)
        except Exception as e:
            messagebox.showerror("error", e)
            return

    # 解密函数
    def decrypt(self):
        try:
            # 获取输入框中的密文和密钥
            ciphertext = self.entry1.get("1.0", "end")
            ciphertext = ciphertext.encode()
            key = self.entry2.get()
            iv = self.entry3.get()
            mode = self.mode_box.get()
            padding = self.padding_box.get()
            blocksize = self.blocksize_box.get()
            blocksize = int(blocksize)

            # 将密钥填充到指定长度
            if len(key) < blocksize / 8:
                messagebox.showerror(
                    "Error",
                    f"The password must contain at least {blocksize / 8} characters.",
                )
                return

            key = key.encode()

            # 根据选择的加密模式和填充方式创建AES对象
            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
            elif mode == "CBC":
                if len(iv) < 16:
                    messagebox.showerror("Error", "The offset length must be 16 bits")
                    return
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)

            ciphertext = base64.b64decode(ciphertext)
            plaintext = cipher.decrypt(ciphertext)

            if padding == "pkcs7":
                plaintext = unpad(plaintext, AES.block_size)
            elif padding == "iso7816":
                plaintext = unpad(plaintext, AES.block_size, "iso7816")
            elif padding == "x923":
                plaintext = unpad(plaintext, AES.block_size, "x923")

            # 解密密文并去除填充
            plaintext = plaintext.decode()

            # 显示解密结果
            self.text.delete(1.0, "end")
            self.text.insert("end", plaintext)
        except Exception as e:
            messagebox.showerror("error", e)
            return


class Base64GUI:
    """base64 Window"""

    def __init__(self, master=None) -> None:
        self.root = ttk.Frame(master)

        input_frame = ttk.LabelFrame(self.root, text="Input")
        input_frame.pack()
        self.input_box = tk.Text(input_frame, height=10)
        self.input_box.pack()
        bframe = tk.Frame(self.root)
        bframe.pack()
        ebtn = ttk.Button(bframe, text="Encrypt", command=self.encrypto)
        ebtn.pack(side=tk.LEFT)
        dbtn = ttk.Button(bframe, text="Decrypt", command=self.decrypto)
        dbtn.pack(side=tk.LEFT)
        output_frame = ttk.LabelFrame(self.root, text="Output")
        output_frame.pack()
        self.output_box = tk.Text(output_frame, height=10)
        self.output_box.pack()

    def encrypto(self):
        input_text = self.input_box.get(1.0, tk.END)
        res = base64.b64encode(input_text.encode("utf-8")).decode("utf-8")
        self.output_box.delete(1.0, tk.END)
        self.output_box.insert(1.0, res)

    def decrypto(self):
        try:
            input_text = self.input_box.get(1.0, tk.END)
            res = base64.b64decode(input_text.encode("utf-8")).decode("utf-8")
            self.output_box.delete(1.0, tk.END)
            self.output_box.insert(1.0, res)
        except Exception as e:
            messagebox.showerror("Error", e)


class MD5GUI:
    """MD5 Window"""

    def __init__(self, master=None):
        self.root = ttk.Frame(master)

        init_data_label = ttk.LabelFrame(self.root, text="Input")
        init_data_label.pack()
        ttk.Button(
            self.root,
            text="MD5",
            width=10,
            command=self.str_trans_to_md5,
        ).pack()

        result_data_label = ttk.LabelFrame(self.root, text="Output")
        result_data_label.pack()

        self.init_data_text = ScrolledText(
            init_data_label, height=10
        )  # Raw data entry box
        self.init_data_text.pack()
        self.result_data_text = ScrolledText(
            result_data_label, height=10
        )  # Processing result presentation
        self.result_data_text.pack()

    def str_trans_to_md5(self):
        src = self.init_data_text.get(1.0, "end").strip().replace("\n", "").encode()
        try:
            hasher = hashlib.md5()
            hasher.update(src)
            res = hasher.hexdigest()
            self.result_data_text.delete(1.0, "end")
            self.result_data_text.insert(1.0, res + "\n")
            self.result_data_text.insert("end", res.upper())
        except Exception:
            self.result_data_text.delete(1.0, "end")
            messagebox.showinfo("Error", "MD5 Falied")


class GenPwdWindow:
    """随即密码生成器"""

    def __init__(self, master=None) -> None:
        self.root = ttk.Frame(master)
        self.dcb = tk.BooleanVar(value=True)  # 数字
        self.lccb = tk.BooleanVar(value=True)  # 小写字母
        self.uccb = tk.BooleanVar(value=True)  # 大写字母
        self.pcb = tk.BooleanVar()  # 字符
        self.l = tk.IntVar(value=8)

        vcmd = (self.root.register(lambda x: re.search(r"^\d+$", x) is not None), "%P")
        ivcmd = (
            self.root.register(
                lambda: messagebox.showerror(
                    "Error", "The password length must be an integer"
                )
            ),
        )
        # 密码长度标签和输入框
        length_label = ttk.Label(self.root, text="Password Length:")
        length_label.grid(row=0, column=0)
        ttk.Entry(
            self.root,
            textvariable=self.l,
            validate="key",
            validatecommand=vcmd,
            invalidcommand=ivcmd,
        ).grid(row=0, column=1, columnspan=4, sticky="w")

        # 密码复杂程度选择
        complexity_label = ttk.Label(self.root, text="Password Complexity:")
        complexity_label.grid(row=1, column=0)
        ttk.Checkbutton(self.root, text="0-9", variable=self.dcb).grid(row=1, column=1)
        ttk.Checkbutton(self.root, text="a-z", variable=self.lccb).grid(row=1, column=2)
        ttk.Checkbutton(self.root, text="A-z", variable=self.uccb).grid(row=1, column=3)
        ttk.Checkbutton(self.root, text="other", variable=self.pcb).grid(
            row=1, column=4
        )

        # 生成密码按钮
        generate_button = ttk.Button(
            self.root, text="Generate Password", command=self.generate_password
        )
        generate_button.grid(row=2, column=0, columnspan=5)

        # 生成密码的标签
        password_label = ttk.Label(self.root, text="Generated Password:")
        password_label.grid(row=3, column=0)

        self.pwd_entry = ttk.Entry(self.root)
        self.pwd_entry.grid(row=3, column=1, columnspan=4, sticky="w")

    def generate_password(self):
        password_length = self.l.get()
        alphabet = string.digits if self.dcb.get() else ""
        alphabet += string.ascii_lowercase if self.lccb.get() else ""
        alphabet += string.ascii_uppercase if self.uccb.get() else ""
        alphabet += string.punctuation if self.pcb.get() else ""
        password = (
            "".join(secrets.choice(alphabet) for _ in range(password_length))
            if alphabet > ""
            else ""
        )
        self.pwd_entry.delete(0, tk.END)
        self.pwd_entry.insert(0, password)


class RegexWindow:
    def __init__(self, master=None) -> None:
        # 创建主窗口
        root = ttk.Frame(master)

        # 创建选项
        options_frame = ttk.Frame(root)
        options_frame.pack()

        # 创建正则表达式输入框
        regex_label = ttk.Label(options_frame, text="Regular expression:")
        regex_label.pack(side=tk.LEFT)
        regex_entry = ttk.Entry(options_frame)
        regex_entry.pack(side=tk.LEFT)

        ignore_case_var = tk.BooleanVar(value=False)
        ignore_case_checkbox = ttk.Checkbutton(
            options_frame, text="Ignore case", variable=ignore_case_var
        )
        ignore_case_checkbox.pack(side=tk.LEFT)

        multi_line_var = tk.BooleanVar(value=False)
        multi_line_checkbox = ttk.Checkbutton(
            options_frame, text="Multiline mode", variable=multi_line_var
        )
        multi_line_checkbox.pack(side=tk.LEFT)
        # 创建查找按钮
        find_button = ttk.Button(
            options_frame,
            text="Search",
            command=lambda: self.find_matches(ignore_case_var, multi_line_var),
        )
        find_button.pack(side=tk.LEFT)

        # 创建文本输入框
        text_label = ttk.LabelFrame(root, text="Input:")
        text_label.pack(padx=10)
        text_entry = ScrolledText(text_label, height=10)
        text_entry.pack()

        # 创建结果显示区域
        result_label = ttk.LabelFrame(root, text="Output:")
        result_label.pack(padx=10)
        result_text = ScrolledText(result_label, height=10)
        result_text.pack()

        st = ScrolledText(root)
        st.insert(
            "1.0",
            """常用正则表达式
一、校验数字的表达式
数字：^[0-9]*$
n位的数字：^\d{n}$
至少n位的数字：^\d{n,}$
m-n位的数字：^\d{m,n}$
零和非零开头的数字：^(0|[1-9][0-9]*)$
非零开头的最多带两位小数的数字：^([1-9][0-9]*)+(\.[0-9]{1,2})?$
带1-2位小数的正数或负数：^(\-)?\d+(\.\d{1,2})$
正数、负数、和小数：^(\-|\+)?\d+(\.\d+)?$
有两位小数的正实数：^[0-9]+(\.[0-9]{2})?$
有1~3位小数的正实数：^[0-9]+(\.[0-9]{1,3})?$
非零的正整数：^[1-9]\d*$ 或 ^([1-9][0-9]*){1,3}$ 或 ^\+?[1-9][0-9]*$
非零的负整数：^\-[1-9][]0-9"*$ 或 ^-[1-9]\d*$
非负整数：^\d+$ 或 ^[1-9]\d*|0$
非正整数：^-[1-9]\d*|0$ 或 ^((-\d+)|(0+))$
非负浮点数：^\d+(\.\d+)?$ 或 ^[1-9]\d*\.\d*|0\.\d*[1-9]\d*|0?\.0+|0$
非正浮点数：^((-\d+(\.\d+)?)|(0+(\.0+)?))$ 或 ^(-([1-9]\d*\.\d*|0\.\d*[1-9]\d*))|0?\.0+|0$
正浮点数：^[1-9]\d*\.\d*|0\.\d*[1-9]\d*$ 或 ^(([0-9]+\.[0-9]*[1-9][0-9]*)|([0-9]*[1-9][0-9]*\.[0-9]+)|([0-9]*[1-9][0-9]*))$
负浮点数：^-([1-9]\d*\.\d*|0\.\d*[1-9]\d*)$ 或 ^(-(([0-9]+\.[0-9]*[1-9][0-9]*)|([0-9]*[1-9][0-9]*\.[0-9]+)|([0-9]*[1-9][0-9]*)))$
浮点数：^(-?\d+)(\.\d+)?$ 或 ^-?([1-9]\d*\.\d*|0\.\d*[1-9]\d*|0?\.0+|0)$
校验字符的表达式
汉字：^[\u4e00-\u9fa5]{0,}$
英文和数字：^[A-Za-z0-9]+$ 或 ^[A-Za-z0-9]{4,40}$
长度为3-20的所有字符：^.{3,20}$
由26个英文字母组成的字符串：^[A-Za-z]+$
由26个大写英文字母组成的字符串：^[A-Z]+$
由26个小写英文字母组成的字符串：^[a-z]+$
由数字和26个英文字母组成的字符串：^[A-Za-z0-9]+$
由数字、26个英文字母或者下划线组成的字符串：^\w+$ 或 ^\w{3,20}$
中文、英文、数字包括下划线：^[\u4E00-\u9FA5A-Za-z0-9_]+$
中文、英文、数字但不包括下划线等符号：^[\u4E00-\u9FA5A-Za-z0-9]+$ 或 ^[\u4E00-\u9FA5A-Za-z0-9]{2,20}$
可以输入含有^%&',;=?$\"等字符：[^%&',;=?$\x22]+
禁止输入含有~的字符：[^~]+
三、特殊需求表达式
Email地址：^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$
域名：[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?
InternetURL：[a-zA-z]+://[^\s]* 或 ^http://([\w-]+\.)+[\w-]+(/[\w-./?%&=]*)?$
手机号码：^(13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}$
电话号码("XXX-XXXXXXX"、"XXXX-XXXXXXXX"、"XXX-XXXXXXX"、"XXX-XXXXXXXX"、"XXXXXXX"和"XXXXXXXX)：^(\(\d{3,4}-)|\d{3.4}-)?\d{7,8}$
国内电话号码(0511-4405222、021-87888822)：\d{3}-\d{8}|\d{4}-\d{7}
电话号码正则表达式（支持手机号码，3-4位区号，7-8位直播号码，1－4位分机号）: ((\d{11})|^((\d{7,8})|(\d{4}|\d{3})-(\d{7,8})|(\d{4}|\d{3})-(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1})|(\d{7,8})-(\d{4}|\d{3}|\d{2}|\d{1}))$)
身份证号(15位、18位数字)，最后一位是校验位，可能为数字或字符X：(^\d{15}$)|(^\d{18}$)|(^\d{17}(\d|X|x)$)
帐号是否合法(字母开头，允许5-16字节，允许字母数字下划线)：^[a-zA-Z][a-zA-Z0-9_]{4,15}$
密码(以字母开头，长度在6~18之间，只能包含字母、数字和下划线)：^[a-zA-Z]\w{5,17}$
强密码(必须包含大小写字母和数字的组合，不能使用特殊字符，长度在 8-10 之间)：^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9]{8,10}$
强密码(必须包含大小写字母和数字的组合，可以使用特殊字符，长度在8-10之间)：^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,10}$
日期格式：^\d{4}-\d{1,2}-\d{1,2}
一年的12个月(01～09和1～12)：^(0?[1-9]|1[0-2])$
一个月的31天(01～09和1～31)：^((0?[1-9])|((1|2)[0-9])|30|31)$
钱的输入格式：
有四种钱的表示形式我们可以接受:"10000.00" 和 "10,000.00", 和没有 "分" 的 "10000" 和 "10,000"：^[1-9][0-9]*$
这表示任意一个不以0开头的数字,但是,这也意味着一个字符"0"不通过,所以我们采用下面的形式：^(0|[1-9][0-9]*)$
一个0或者一个不以0开头的数字.我们还可以允许开头有一个负号：^(0|-?[1-9][0-9]*)$
这表示一个0或者一个可能为负的开头不为0的数字.让用户以0开头好了.把负号的也去掉,因为钱总不能是负的吧。下面我们要加的是说明可能的小数部分：^[0-9]+(.[0-9]+)?$
必须说明的是,小数点后面至少应该有1位数,所以"10."是不通过的,但是 "10" 和 "10.2" 是通过的：^[0-9]+(.[0-9]{2})?$
这样我们规定小数点后面必须有两位,如果你认为太苛刻了,可以这样：^[0-9]+(.[0-9]{1,2})?$
这样就允许用户只写一位小数.下面我们该考虑数字中的逗号了,我们可以这样：^[0-9]{1,3}(,[0-9]{3})*(.[0-9]{1,2})?$
1到3个数字,后面跟着任意个 逗号+3个数字,逗号成为可选,而不是必须：^([0-9]+|[0-9]{1,3}(,[0-9]{3})*)(.[0-9]{1,2})?$
备注：这就是最终结果了,别忘了"+"可以用"*"替代如果你觉得空字符串也可以接受的话(奇怪,为什么?)最后,别忘了在用函数时去掉去掉那个反斜杠,一般的错误都在这里
xml文件：^([a-zA-Z]+-?)+[a-zA-Z0-9]+\\.[x|X][m|M][l|L]$
中文字符的正则表达式：[\u4e00-\u9fa5]
双字节字符：[^\x00-\xff] (包括汉字在内，可以用来计算字符串的长度(一个双字节字符长度计2，ASCII字符计1))
空白行的正则表达式：\n\s*\r (可以用来删除空白行)
HTML标记的正则表达式：<(\S*?)[^>]*>.*?|<.*? /> ( 首尾空白字符的正则表达式：^\s*|\s*$或(^\s*)|(\s*$) (可以用来删除行首行尾的空白字符(包括空格、制表符、换页符等等)，非常有用的表达式)
腾讯QQ号：[1-9][0-9]{4,} (腾讯QQ号从10000开始)
中国邮政编码：[1-9]\d{5}(?!\d) (中国邮政编码为6位数字)
IPv4地址：((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}""",
        )
        st.configure(state="disabled")
        st.pack(padx=10, pady=10)

        self.root = root
        self.regex_entry = regex_entry
        self.text_entry = text_entry
        self.result_text = result_text

    def find_matches(self, ignore_case_var, multi_line_var):
        regex = self.regex_entry.get()
        text = self.text_entry.get("1.0", tk.END)
        flags = 0
        if ignore_case_var.get():  # 如果勾选了忽略大小写
            flags |= re.IGNORECASE
        if multi_line_var.get():  # 如果勾选了多行模式
            flags |= re.MULTILINE

        try:
            matches = re.finditer(regex, text, flags)
            self.result_text.delete(1.0, tk.END)
            if matches:
                for item in matches:
                    self.result_text.insert(tk.END, f"Match: {item}\n")
            else:
                self.result_text.insert(tk.END, "No matches found.\n")
        except re.error as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Error: {e}")


class TimestampWindow:
    """时间戳转换工具"""

    def __init__(self, master=None):
        self.root = ttk.Frame(master)
        # 时间戳转日期时间
        ttk.Label(self.root, text="Timestamp:").grid(row=0, column=0)
        self.timestamp_entry = ttk.Entry(self.root)
        self.timestamp_entry.grid(row=0, column=1)
        ttk.Button(
            self.root, text="transform", command=self.timestamp_to_datetime
        ).grid(row=0, column=2)
        ttk.Label(self.root, text="Datetime:").grid(row=0, column=3)
        self.datetime_entry = ttk.Entry(self.root)
        self.datetime_entry.grid(row=0, column=4)

        # 日期时间转时间戳
        ttk.Label(self.root, text="DateTime:").grid(row=1, column=0)
        self.date_entry = ttk.Entry(self.root)
        self.date_entry.grid(row=1, column=1)
        ttk.Button(
            self.root, text="transform", command=self.datetime_to_timestamp
        ).grid(row=1, column=2)
        ttk.Label(self.root, text="Timestamp:").grid(row=1, column=3)
        self.time_entry = ttk.Entry(self.root)
        self.time_entry.grid(row=1, column=4)
        ttk.Label(self.root, text="(YYYY-MM-DD HH:MM:SS)").grid(
            row=2, column=0, columnspan=2
        )

    def timestamp_to_datetime(self):
        timestamp = self.timestamp_entry.get()
        if re.search(r"^\d+$", timestamp) is None:
            messagebox.showinfo("Warning", "Invalid timestamp!")
            return

        timestamp = int(timestamp)
        try:
            dt = datetime.datetime.fromtimestamp(timestamp)
            self.datetime_entry.delete(0, tk.END)
            self.datetime_entry.insert(0, str(dt))
        except ValueError:
            messagebox.showinfo("Warning", "Invalid timestamp!")

    def datetime_to_timestamp(self):
        date_str = self.date_entry.get()
        if (
            re.search(r"^\d{4}-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}$", date_str)
            is None
        ):
            messagebox.showinfo("Warning", "Invalid datetime format!")
            return

        try:
            dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
            timestamp = int(dt.timestamp())
            self.time_entry.delete(0, tk.END)
            self.time_entry.insert(0, str(timestamp))
        except ValueError:
            messagebox.showinfo("Warning", "Invalid datetime format!")


root = tk.Tk()
root.title("tk toolbox")

notebook = ttk.Notebook(root)
aes_frame = AesGui(notebook)
notebook.add(aes_frame.root, text="AES")
md5_frame = MD5GUI(notebook)
notebook.add(md5_frame.root, text="MD5")
base64_frame = Base64GUI(notebook)
notebook.add(base64_frame.root, text="Base64")
regex_frame = RegexWindow(notebook)
notebook.add(regex_frame.root, text="Regex")
timestamp_frame = TimestampWindow(notebook)
notebook.add(timestamp_frame.root, text="Timestamp")
password_frame = GenPwdWindow(notebook)
notebook.add(password_frame.root, text="Password")
notebook.pack(fill="both", expand=True)

root.mainloop()
