from infi.systray import SysTrayIcon
import zmq
from PIL import Image
import PIL
import mss
import io
import webbrowser
import threading
from os.path import exists
import json
import time
import pyautogui
import datetime
from win32api import *
from win32gui import *
import win32gui 
import win32con

class WindowsBalloonTip:
    def __init__(self, title, msg):
        # Register the Window class.
        wc = WNDCLASS()
        hinst = wc.hInstance = GetModuleHandle(None)
        wc.lpszClassName = "PythonTaskbar"
        wc.lpfnWndProc = self.wndProc
        classAtom = RegisterClass(wc)
        # Create the Window.
        style = win32con.WS_OVERLAPPED | win32con.WS_SYSMENU
        self.hwnd = CreateWindow( classAtom, "Taskbar", style, \
                0, 0, win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT, \
                0, 0, hinst, None)
        UpdateWindow(self.hwnd)
        iconPathName = "C:/OpenRMM/Agent/icon.ico"
        icon_flags = win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE
        try:
           hicon = LoadImage(hinst, iconPathName, \
                    win32con.IMAGE_ICON, 0, 0, icon_flags)
        except:
          hicon = LoadIcon(0, win32con.IDI_APPLICATION)
        flags = NIF_ICON | NIF_MESSAGE | NIF_TIP
        nid = (self.hwnd, 0, flags, win32con.WM_USER+20, hicon, "tooltip")
        Shell_NotifyIcon(NIM_ADD, nid)
        Shell_NotifyIcon(NIM_MODIFY, \
                         (self.hwnd, 0, NIF_INFO, win32con.WM_USER+20,\
                          hicon, "Balloon  tooltip",msg,200,title))
        win32gui.PumpMessages()
        # self.show_balloon(title, msg)
        time.sleep(10)
        DestroyWindow(self.hwnd)

    def OnClick(self, hwnd, msg, wparam, lparam):
        webbrowser.open("https://dev.openrmm.io/", new=0, autoraise=True)

    def OnDestroy(self, hwnd, msg, wparam, lparam):
        nid = (self.hwnd, 0)
        Shell_NotifyIcon(NIM_DELETE, nid)
        PostQuitMessage(0) # Terminate the app.

    def wndProc(self, hWnd, message, wParam, lParam): 
        if message == 1044:          
            if lParam == 1029: 
                self.OnClick(hWnd, message, wParam, lParam)
                self.OnDestroy(hWnd, message, wParam, lParam)
            elif lParam == 1028:
                self.OnDestroy(hWnd, message, wParam, lParam)

def balloon_tip(title, msg):
    w=WindowsBalloonTip(title, msg)


context = zmq.Context()
socket = context.socket(zmq.PAIR)
socket.connect("tcp://localhost:5554")

def button_self_service_portal(systray):
    AgentSettings = read_config_file()
    if("Setup" in AgentSettings):
        if("ID" in AgentSettings["Setup"]):
            ID = AgentSettings["Setup"]["ID"]
            webbrowser.open("https://dev.openrmm.io/?page=Asset_Portal&ID=" + str(ID) , new=0, autoraise=True)

def button_manage_agent(systray):
    AgentSettings = read_config_file()
    webbrowser.open("https://dev.openrmm.io/", new=0, autoraise=True)

def screenshot(systray=None):
    try:
        with mss.mss() as sct:
            # Get rid of the first, as it represents the "All in One" monitor:
            for num, monitor in enumerate(sct.monitors[1:], 1):
                # Get raw pixels from the screen
                sct_img = sct.grab(monitor)
                # Create the Image
                screenshot = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                screenshot = screenshot.resize((800, 450), PIL.Image.ANTIALIAS) #16:9 ratio

                with io.BytesIO() as output:
                    screenshot.save(output, format='JPEG')
                    send = {"source":"ui", "type":"screenshot", "monitor_number":str(num), "value":output.getvalue().decode("ISO-8859-1")}
                socket.send_unicode(json.dumps(send))
    except Exception as e:
        print(e)

def alert(payload):
    try:
        response = ""
        if(payload["Type"] == "alert"): response = pyautogui.alert(payload["Message"], payload["Title"], 'Okay')
        if(payload["Type"] == "confirm"): response = pyautogui.confirm(payload["Message"], payload["Title"], ['Yes', 'No'])
        if(payload["Type"] == "prompt"): response = pyautogui.prompt(payload["Message"], payload["Title"], '')
        if(payload["Type"] == "password"): response = pyautogui.password(payload["Message"], payload["Title"], '', mask='*')
        send = {"source":"ui", "type":"alert", "value": ""}
        socket.send_unicode(json.dumps(send))
    except Exception as e:
        print(e)
    
def read_config_file():
    try:
        if(exists("C:\OpenRMM\Agent\OpenRMM.json")): 
            f = open("C:\OpenRMM\Agent\OpenRMM.json", "r")
            return json.loads(f.read())
        else:
            return {}
    except Exception as e:
        print(e)


# Process Agent UI System Tray Icon Messages
def socket_recieve():
    while True:
        try:
            data = socket.recv()
            if(data):
                data = json.loads(data)
                time = str(datetime.datetime.now().strftime("%m-%d-%y %I:%M:%S %p"))
                print(time + ": Getting " + data["type"] + " requested by: " + data['source'])
                if(data["source"] == "service"):
                    if(data["type"] == "screenshot"): screenshot()
                    if(data["type"] == "alert"): alert(data["value"])  
        except Exception as e:
            print(e)


thread_socket = threading.Thread(target=socket_recieve, args=[]).start()
menu_options = (("Self-Service Portal", None, button_self_service_portal), ("Manage Agent", None, button_manage_agent))
systray = SysTrayIcon("../icon.ico", "OpenRMM Agent", menu_options)
systray.start()


w = balloon_tip("OpenRMM Agent", "Agent Started")