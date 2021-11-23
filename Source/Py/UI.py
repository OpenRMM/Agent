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

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5554")

def button_self_service_portal(systray):
    AgentSettings = read_config_file()
    if("Setup" in AgentSettings):
        if("ID" in AgentSettings["Setup"]):
            ID = AgentSettings["Setup"]["ID"]
            webbrowser.open("https://dev.openrmm.io/?page=Asset_Portal&ID=" + str(ID) , new=0, autoraise=True)

def button_screenshot(systray): screenshot()
def loop_screenshot():
    loopCount = 0
    while True:
        AgentSettings = read_config_file()
        time.sleep(10)
        loopCount = loopCount + 1
        if (loopCount == (6 * AgentSettings['Configurable']['Interval']['screenshot']) and AgentSettings['Configurable']['Interval']['screenshot'] != "0"): # Every x minutes
            loopCount = 0
            screenshot()


def screenshot():
    try:
        with mss.mss() as sct:
            # Get rid of the first, as it represents the "All in One" monitor:
            for num, monitor in enumerate(sct.monitors[1:], 1):
                # Get raw pixels from the screen
                sct_img = sct.grab(monitor)
                # Create the Image
                screenshot = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                screenshot = screenshot.resize((600, 337), PIL.Image.ANTIALIAS) #16:9 ratio

                with io.BytesIO() as output:          
                    screenshot.save(output, format='JPEG')
                    send = {"type":"screenshot", "monitor_number":str(num), "value":output.getvalue().decode("ISO-8859-1")}

                socket.send_unicode(json.dumps(send))
                message = socket.recv()
                print(message)
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

thread_screenshots = threading.Thread(target=loop_screenshot, args=[]).start()
menu_options = (("Self-Service Portal", None, button_self_service_portal), ("Send Screenshot", None, button_screenshot))
systray = SysTrayIcon("../icon.ico", "OpenRMM Agent", menu_options)
systray.start()