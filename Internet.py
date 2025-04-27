import requests
import json
import yaml
import os
import tkinter as tk
from tkinter import messagebox, simpledialog
import sys
import winreg
from PIL import Image

# 获取程序运行的目录
if getattr(sys, 'frozen', False):
    current_dir = os.path.dirname(sys.executable)
else:
    current_dir = os.path.dirname(os.path.abspath(__file__))

# 修改配置文件路径到 LOCALAPPDATA 下的 XuanLuo/wxgyautologin 
if os.name == 'nt': 
    local_appdata = os.environ.get('LOCALAPPDATA')
    config_dir = os.path.join(local_appdata, 'XuanLuo', 'wxgyautologin')
    os.makedirs(config_dir, exist_ok=True)
    CONFIG_FILE = os.path.join(config_dir, 'config.yml')
else:
    CONFIG_FILE = os.path.join(current_dir, "config.yml")

# 默认配置
DEFAULT_CONFIG = {
    "account": "账号",
    "password": "密码",
    "operator": "cmcc",
    "auto_start": False,
    "auto_login": False 
}

def load_config():
    """加载配置文件，如果不存在则创建默认配置"""
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
        print(f"配置文件 {CONFIG_FILE} 不存在，已创建默认配置。")
        return DEFAULT_CONFIG
    else:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

def show_popup(title, message):
    messagebox.showinfo(title, message)

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

def input_config():
    config = load_config()
    account = simpledialog.askstring("输入账号", "请输入账号:", initialvalue=config.get("account"))
    if account is None:
        return
    password = simpledialog.askstring("输入密码", "请输入密码:", initialvalue=config.get("password"), show='*')
    if password is None:
        return
    operator = simpledialog.askstring("输入运营商", "请输入运营商 (cmcc 移动 或 telecom 电信):", initialvalue=config.get("operator"))
    if operator is None:
        return
    new_config = {
        "account": account,
        "password": password,
        "operator": operator,
        "auto_start": config.get("auto_start", False)
    }
    save_config(new_config)
    return new_config

def set_auto_start(enable):
    """设置开机自启"""
    script_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_ALL_ACCESS)
        app_name = os.path.splitext(os.path.basename(script_path))[0]
        if enable:
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, script_path)
            message = "开机自启设置成功"
        else:
            try:
                winreg.DeleteValue(key, app_name)
                message = "开机自启已取消"
            except FileNotFoundError:
                message = "开机自启原本就未设置，无需取消"
        winreg.CloseKey(key)
        return True, message
    except Exception as e:
        error_message = f"开机自启设置失败: {e}"
        return False, error_message

def main():
    config = load_config()
    account = config.get("account")
    password = config.get("password")
    operator = config.get("operator")

    url1 = "http://172.31.0.138/drcom/chkstatus?callback=dr1002&jsVersion=4.X&v=10496&lang=zh"
    try:
        response = requests.get(url1)
        response.raise_for_status()
        json_str = response.text.strip()
        json_str = json_str[len("dr1002("):-1]
        data = json.loads(json_str)
        v46ip = data.get("v46ip")
        if not v46ip:
            raise ValueError("v46ip 字段未找到或为空")
    except requests.exceptions.RequestException as e:
        show_popup("错误", f"请求失败: {e}")
        return
    except json.JSONDecodeError as e:
        show_popup("错误", f"JSON 解析失败: {e}")
        return
    except ValueError as e:
        show_popup("错误", str(e))
        return

    url2 = (
        f"http://172.31.0.138:801/eportal/portal/login?callback=dr1003&login_method=1&"
        f"user_account=%2C0%2C{account}%40{operator}&user_password={password}&"
        f"wlan_user_ip={v46ip}&wlan_user_ipv6=&wlan_user_mac=000000000000&"
        f"wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v=2888&lang=zh"
    )
    url3 = (
        f"http://172.31.0.138:801/eportal/portal/login?callback=dr1003&login_method=1&"
        f"user_account=%2C0%2C********%40{operator}&user_password=********&"
        f"wlan_user_ip={v46ip}&wlan_user_ipv6=&wlan_user_mac=000000000000&"
        f"wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v=2888&lang=zh"
    )
    print("登录数据已生成", url3)

    try:
        response = requests.get(url2)
        response.raise_for_status()
        result = response.text
        print("登录请求成功:", result)
        show_popup("成功", f"登录请求成功: {result}")
    except requests.exceptions.RequestException as e:
        print("登录请求失败:", e)
        show_popup("错误", f"登录请求失败: {e}")

def clear_config():
    """清空配置文件，恢复默认配置"""
    save_config(DEFAULT_CONFIG)
    show_popup("提示", "配置文件已清空，恢复为默认配置。")

def create_gui():
    root = tk.Tk()
    root.title("璇洛——校园网自动登录")
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(base_path, '1.ico')
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.geometry("500x330")  
    root.configure(bg="#f0f0f0")

    config = load_config()
    account = config.get("account")
    password = config.get("password")
    operator = config.get("operator")
    auto_start = config.get("auto_start", False)
    auto_login = config.get("auto_login", False)

    label_font = ("Arial", 12)
    button_font = ("Arial", 12, "bold")


    input_frame = tk.Frame(root, bg="#f0f0f0")
    input_frame.pack(pady=20)

    tk.Label(input_frame, text="账号:", font=label_font, bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="e")
    account_entry = tk.Entry(input_frame, font=label_font)
    account_entry.insert(0, account)
    account_entry.grid(row=0, column=1, padx=10, pady=5)
    account_entry.bind("<FocusOut>", lambda event: save_current_config(account_entry.get(), password_entry.get(), operator_var.get()))

    tk.Label(input_frame, text="密码:", font=label_font, bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=5, sticky="e")
    password_entry = tk.Entry(input_frame, font=label_font)
    password_entry.insert(0, password)
    password_entry.grid(row=1, column=1, padx=10, pady=5)
    password_entry.bind("<FocusOut>", lambda event: save_current_config(account_entry.get(), password_entry.get(), operator_var.get()))

    tk.Label(input_frame, text="运营商:", font=label_font, bg="#f0f0f0").grid(row=2, column=0, padx=10, pady=5, sticky="e")
    operator_var = tk.StringVar(root)
    operator_mapping = {
        "cmcc": "中国移动",
        "telecom": "中国电信"
    }
    reverse_operator_mapping = {v: k for k, v in operator_mapping.items()}
    display_operator = operator_mapping.get(operator, "中国移动")
    operator_var.set(display_operator)

    def update_operator(*args):
        display_value = operator_var.get()
        internal_value = reverse_operator_mapping.get(display_value, "cmcc")
        save_current_config(account_entry.get(), password_entry.get(), internal_value)

    operator_menu = tk.OptionMenu(input_frame, operator_var, "中国移动", "中国电信", command=update_operator)
    operator_menu.config(font=label_font)
    operator_menu.grid(row=2, column=1, padx=10, pady=5)

    checkbox_frame = tk.Frame(root, bg="#f0f0f0")
    checkbox_frame.pack(pady=10)

    auto_start_var = tk.BooleanVar()
    auto_start_var.set(auto_start)
    auto_start_checkbox = tk.Checkbutton(checkbox_frame, text="开机自启", variable=auto_start_var,
                                         command=lambda: save_auto_start_config(auto_start_var.get()),
                                         font=label_font, bg="#f0f0f0")
    auto_start_checkbox.pack(side=tk.LEFT, padx=20)

    auto_login_var = tk.BooleanVar()
    auto_login_var.set(auto_login)
    auto_login_checkbox = tk.Checkbutton(checkbox_frame, text="软件启动自动登录", variable=auto_login_var,
                                         command=lambda: save_auto_login_config(auto_login_var.get()),
                                         font=label_font, bg="#f0f0f0")
    auto_login_checkbox.pack(side=tk.LEFT, padx=20)

    button_frame = tk.Frame(root, bg="#f0f0f0")
    button_frame.pack(pady=20)

    login_button = tk.Button(button_frame, text="登录", command=main, font=button_font, bg="#2196F3", fg="white")
    login_button.pack(side=tk.LEFT, padx=10)

    clear_button = tk.Button(button_frame, text="清空配置", command=clear_config, font=button_font, bg="#FF5722", fg="white")
    clear_button.pack(side=tk.LEFT, padx=10)

    root.mainloop()

def save_auto_login_config(enable):
    config = load_config()
    config["auto_login"] = enable
    save_config(config)

def save_current_config(account, password, operator):
    config = load_config()
    config["account"] = account
    config["password"] = password
    config["operator"] = operator
    save_config(config)

def save_auto_start_config(enable):
    config = load_config()
    config["auto_start"] = enable
    save_config(config)
    success, message = set_auto_start(enable)
    show_popup("开机自启设置结果", message)

def process_image(image_path):
    img = Image.open(image_path)
    if 'icc_profile' in img.info:
        del img.info['icc_profile']
    img.save(image_path)

if __name__ == "__main__":
    config = load_config()
    if config.get("auto_login", False):
        main()
    create_gui()
