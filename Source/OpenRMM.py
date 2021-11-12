#!/usr/bin/env python3

import os
from os.path import exists
import wmi
import paho.mqtt.client as mqtt
import json
import time, datetime
import subprocess
import threading
import pythoncom
import pyautogui
import io, sys
import PIL
import win32serviceutil, win32event, win32service, win32con, win32evtlogutil, win32evtlog, win32security, win32api, winerror
from win32com.client import GetObject
import servicemanager
import pkg_resources
import urllib.request
import scandir
from random import randint
import traceback
import socket
import datetime
import rsa
from cryptography.fernet import Fernet
from dictdiffer import diff, patch, swap, revert
import speedtest

################################# SETUP ##################################
MQTT_Server = "***"
MQTT_Username = "****"
MQTT_Password = "****"
MQTT_Port = 1884

Service_Name = "OpenRMMAgent"
Service_Display_Name = "OpenRMM Agent"
Service_Description = "A free open-source remote monitoring & management tool."

Agent_Version = "1.9.8"

LOG_File = "C:\OpenRMM.log"
DEBUG = False

###########################################################################

required = {'paho-mqtt', 'pyautogui', 'pywin32', 'wmi', 'pillow', 'scandir', 'speedtest-cli', 'cryptography', 'rsa', 'dictdiffer'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if(len(missing) > 0):
    print("Missing Modules, please install with the command: python -m pip install modulename")
    print(missing)
    print("Attempting to install modules")
    python = sys.executable
    subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)
    print("Please restart service and try again.")
    sys.exit()

class OpenRMMAgent(win32serviceutil.ServiceFramework):
    _svc_name_ = Service_Name
    _svc_display_name_ = Service_Display_Name
    _svc_description_ = Service_Description

    def str_diff_parse(self, str_diff):
        return [tuple(literal_eval(y) for y in re.findall(r"\[('?\w+'?)\]", x)) for x in str_diff]


    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isrunning = False

    def SvcDoRun(self):
        try:
            print("   ____                   _____  __  __ __  __ ")
            print("  / __ \                 |  __ \|  \/  |  \/  |")
            print(" | |  | |_ __   ___ _ __ | |__) | \  / | \  / |")
            print(" | |  | | '_ \ / _ \ '_ \|  _  /| |\/| | |\/| |")
            print(" | |__| | |_) |  __/ | | | | \ \| |  | | |  | |")
            print("  \____/| .__/ \___|_| |_|_|  \_\_|  |_|_|  |_|")
            print("        | |                                    ")
            print("        |_|                                    ")
            print("Github: https://github.com/OpenRMM/")
            print("Created By: Brad & Brandon Sanders")
            print("")
            os.system('color B')
            time.sleep(0.5)  

            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,servicemanager.PYS_SERVICE_STARTED,(self._svc_name_, ''))
            self.AgentLog = []
            self.isrunning = True
            self.log("Setup", "Agent Starting")
            self.session_id = str(randint(1000000000000000, 1000000000000000000))
            self.AgentSettings = {}
            self.MQTT_flag_connected = 0
            self.rateLimit = 120
            self.lastRan = {}
            self.ignoreRateLimit = ["getFilesystem", "setAlert", "getEventLogs"]
            self.Cache = {}

            try:
                if(exists("C:\OpenRMM.json")):
                    self.log("Setup", "Getting data from C:\OpenRMM.json")
                    f = open("C:\OpenRMM.json", "r")
                    self.AgentSettings = json.loads(f.read())
                    self.Public_Key = rsa.PublicKey.load_pkcs1(self.AgentSettings["Setup"]["Public_Key"].encode('utf8'))
                else:
                    self.log("Read ID From File", "Could not get data from file: C:\OpenRMM.json, file dont exist", "Warn")
            except Exception as e:
                self.log("Read ID From File", e, "Error")

            try:
                self.log("Setup", "Starting MQTT")
                self.mqtt = mqtt.Client(client_id=self.session_id, clean_session=True)
                self.mqtt.username_pw_set(MQTT_Username, MQTT_Password)
                self.mqtt.will_set(self.session_id + "/Status", "0", qos=1, retain=True)
                self.mqtt.connect(MQTT_Server, port=MQTT_Port)
                self.mqtt.subscribe(self.session_id + "/Commands/#", qos=1)
                self.mqtt.on_message = self.on_message
                self.mqtt.on_connect = self.on_connect
                self.mqtt.on_disconnect = self.on_disconnect
                self.mqtt.loop_start()
            except Exception as e:
                self.log("MQTT Setup", e, "Error")

            self.log("Setup", "Starting WMI")
            pythoncom.CoInitialize()
            self.wmimain = wmi.WMI()
            self.main()

        except Exception as e:
            if(DEBUG): print(traceback.format_exc())

    def SvcStop(self):
        self.isrunning = False
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)  

    def main(self):
        while self.isrunning: time.sleep(0.1)

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, rc):
        self.MQTT_flag_connected = 1
        self.log("MQTT", "Connected to server: " + MQTT_Server + " with result code " + str(rc))
        if(exists("C:\OpenRMM.json") == False):
            self.log("MQTT", "Sending New Agent command to server")
            self.mqtt.publish(self.session_id + "/Agent/New", "true", qos=1, retain=False)
        else:
            if("Setup" in self.AgentSettings):
                self.getReady()

    def on_disconnect(self, xclient, userdata, rc):
        self.MQTT_flag_connected = 0
        self.log("MQTT", "Unexpected disconnection", "Warn")

    def on_message(self, client, userdata, message):
        print("MQTT: Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))

        # Ready is sent on agent start, first step in connection is public key exchange
        if (str(message.topic) == self.session_id + "/Commands/New"):
            self.AgentSettings["Setup"] = json.loads(str(message.payload, 'utf-8'))
            self.log("MQTT", "Got ID From server, Setting Up Agent with ID: " + str(self.AgentSettings["Setup"]["ID"]))
            if("Setup" in self.AgentSettings):
                self.getReady()
        
        if(str(message.topic) == str(self.AgentSettings["Setup"]["ID"]) + "/Commands/Ready"):
            self.AgentSettings["Setup"] = json.loads(str(message.payload, 'utf-8'))
            self.log("MQTT", "Setting Up Agent with ID: " + str(self.AgentSettings["Setup"]["ID"]))

            # Save setup to File
            f = open("C:\OpenRMM.json", "w")
            f.write(json.dumps(self.AgentSettings))
            f.close()
            self.getSet()

        # Server has everything it needs for us to start
        if (str(message.topic) == str(self.AgentSettings["Setup"]["ID"]) + "/Commands/Go"):
            self.Go()

        # Sync message recieved from server, update keys
        if (str(message.topic) == str(self.AgentSettings["Setup"]["ID"]) + "/Commands/Sync"):
            self.AgentSettings["Setup"] = json.loads(str(message.payload, 'utf-8'))
            self.getSet("Sync")

        # Make sure we have the base settings, ID, Salt then start listining to commands
        if( "Setup" in self.AgentSettings):
            try:
                # Process Commands
                command = message.topic.split("/")
                if(command[1] == "Commands"):
                    # Command Prompt
                    if(command[2] == "CMD"):
                        encMessage = self.Fernet.encrypt(json.dumps(self.CMD(message.payload)).encode())
                        self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/CMD", encMessage, qos=1)
                    # Other Commands
                    elif(command[2][0:3] == "get" or command[2][0:3] == "set"): 
                        threading.Thread(target=self.startThread, args=[command[2], False, message.payload.decode('utf-8')]).start()
                self.command = {}
            except Exception as e:
                self.log("Commands", e, "Error")

    def getReady(self):
        # Prep MQTT
        self.mqtt.unsubscribe(self.session_id + "/Commands/#")
        self.mqtt.subscribe(str(self.AgentSettings["Setup"]["ID"]) + "/Commands/#", qos=1)

        # Send ready to server
        payload = {"Session_ID":self.session_id}
        self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Agent/Ready", json.dumps(payload), qos=1, retain=False)

    def getSet(self, setType="Startup"):
        self.Public_Key = rsa.PublicKey.load_pkcs1(self.AgentSettings["Setup"]["Public_Key"].encode('utf8'))

        # Generate salt
        self.AgentSettings["Setup"]["salt"] = str(Fernet.generate_key(), "utf-8")
        self.Fernet = Fernet(self.AgentSettings["Setup"]["salt"])
        print("Salt is: " + self.AgentSettings["Setup"]["salt"])

        # Send RSA encrypted key & session_id to the server
        self.log("Encryption", "Sending salt to server")
        RSAEncryptedSalt = rsa.encrypt(self.AgentSettings["Setup"]["salt"].encode(), self.Public_Key)
        
        if(setType == "Startup"):
            self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Agent/Set", RSAEncryptedSalt, qos=1, retain=False)
        elif(setType == "Sync"):
            self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Agent/Sync", RSAEncryptedSalt, qos=1, retain=False)

    def Go(self):
        # Changing status to Online
        self.mqtt.publish(self.session_id + "/Status", "1", qos=1, retain=True)

        self.log("Start", "Recieved Go command from server. Agent Version: " + Agent_Version)

        # Check if got agent settings here, if not load defaults
        self.log("Start", "Waiting for Agent Settings")
        count = 0
        while (count <= 5):
            count = count + 1
            time.sleep(1)
            if(count == 5):
                if("Configurable" not in self.AgentSettings): self.setAgentDefaults()

        # Creating Threads
        if(self.MQTT_flag_connected == 1):
            self.log("Start", "Threads: Starting")
            self.threadHeartbeat = threading.Thread(target=self.startThread, args=["getHeartbeat", True]).start()
            self.threadAgentLog = threading.Thread(target=self.startThread, args=["getAgentLog", True]).start()
            self.threadGeneral = threading.Thread(target=self.startThread, args=["getGeneral", True]).start()
            self.threadBIOS = threading.Thread(target=self.startThread, args=["getBIOS", True]).start()
            self.threadStartup = threading.Thread(target=self.startThread, args=["getStartup", True]).start()
            self.threadOptionalFeatures = threading.Thread(target=self.startThread, args=["getOptionalFeatures", True]).start()
            self.threadProcesses = threading.Thread(target=self.startThread, args=["getProcesses", True]).start()
            self.threadServices = threading.Thread(target=self.startThread, args=["getServices", True]).start()
            self.threadUserAccounts = threading.Thread(target=self.startThread, args=["getUsers", True]).start()
            self.threadVideoConfiguration = threading.Thread(target=self.startThread, args=["getVideoConfiguration", True]).start()
            self.threadLogicalDisk = threading.Thread(target=self.startThread, args=["getLogicalDisk", True]).start()
            self.threadMappedLogicalDisk = threading.Thread(target=self.startThread, args=["getMappedLogicalDisk", True]).start()
            self.threadPhysicalMemory = threading.Thread(target=self.startThread, args=["getPhysicalMemory", True]).start()
            self.threadPointingDevice = threading.Thread(target=self.startThread, args=["getPointingDevice", True]).start()
            self.threadKeyboard = threading.Thread(target=self.startThread, args=["getKeyboard", True]).start()
            self.threadBaseBoard = threading.Thread(target=self.startThread, args=["getBaseBoard", True]).start()
            self.threadDesktopMonitor = threading.Thread(target=self.startThread, args=["getDesktopMonitor", True]).start()
            self.threadPrinter = threading.Thread(target=self.startThread, args=["getPrinters", True]).start()
            self.threadNetworkLoginProfile = threading.Thread(target=self.startThread, args=["getNetworkLoginProfile", True]).start()
            self.threadNetworkAdapters = threading.Thread(target=self.startThread, args=["getNetworkAdapters", True]).start()
            self.threadPnPEntity = threading.Thread(target=self.startThread, args=["getPnPEntities", True]).start()
            self.threadSoundDevice = threading.Thread(target=self.startThread, args=["getSoundDevices", True]).start()
            self.threadSCSIController = threading.Thread(target=self.startThread, args=["getSCSIController", True]).start()
            self.threadProduct = threading.Thread(target=self.startThread, args=["getProducts", True]).start()
            self.threadProcessor = threading.Thread(target=self.startThread, args=["getProcessor", True]).start()
            self.threadFirewall = threading.Thread(target=self.startThread, args=["getFirewall", True]).start()
            self.threadAgent = threading.Thread(target=self.startThread, args=["getAgent", True]).start()
            self.threadBattery = threading.Thread(target=self.startThread, args=["getBattery", True]).start()
            self.threadFilesystem = threading.Thread(target=self.startThread, args=["getFilesystem", True, {"data":"C:\\"}]).start()
            self.threadSharedDrives = threading.Thread(target=self.startThread, args=["getSharedDrives", True]).start()
            self.threadEventLogs_System = threading.Thread(target=self.startThread, args=["getEventLog_System", True]).start()
            self.threadEventLogs_Application = threading.Thread(target=self.startThread, args=["getEventLog_Application", True]).start()
            self.threadEventLogs_Security = threading.Thread(target=self.startThread, args=["getEventLog_Security", True]).start()
            self.threadEventLogs_Setup = threading.Thread(target=self.startThread, args=["getEventLog_Setup", True]).start()
            self.threadScreenshot = threading.Thread(target=self.startThread, args=["getScreenshot", True]).start()
            self.log("Start", "Threads: Started")

            # Send these only once on startup
            #self.threadRegistry = threading.Thread(target=self.startThread, args=["getRegistry", False]).start()
            #self.threadWindowsActivation = threading.Thread(target=self.startThread, args=["getWindowsActivation", False]).start()
            #self.threadOklaSpeedtest = threading.Thread(target=self.startThread, args=["getOklaSpeedtest", False]).start()
            #self.threadAgentLog = threading.Thread(target=self.startThread, args=["getAgentLog", False]).start()
            #self.threadAgentSettings = threading.Thread(target=self.startThread, args=["getAgentSettings", False]).start()  
        else:
            self.log("Start", "MQTT is not connected", "Warn")   

    # Log, Type: Info, Warn, Error
    def log(self, title, message, errorType="Info"):
        print(errorType + " - " + "Title: " + title + ", Message: " + str(message))
        try:
            logEvent = {}
            logEvent["Title"] = title 
            logEvent["Message"] = str(message)
            logEvent["Type"] = errorType
            logEvent["Time"] = str(datetime.datetime.now())
            self.AgentLog.append(logEvent)
            
            f = open(LOG_File, "a")
            f.write(str(datetime.datetime.now()) + " " + errorType + " - " + "Title: " + title + ", Message: " + str(message) + "\n")
            f.close()
        except Exception as e:
            print("Error saving to log file")
            print(e)
            if(DEBUG): print(traceback.format_exc())

    # Start Thread
    def startThread(self, functionName, loop=False, payload="{}"):
        try:
            self.log("Thread", "Calling Function: " + functionName[3:])
            if(self.MQTT_flag_connected == 1):
                pythoncom.CoInitialize()
                loopCount = 0
                data = {}
                # Set Default Value 
                if(functionName[3:] not in self.Cache): self.Cache[functionName[3:]] = ""

                # Send Data on Startup and on Threads
                if(loop == True and functionName[0:3] == "get" and functionName in self.AgentSettings['Configurable']['Interval']):
                    # Get and Send Data on Startup
                    self.log("Thread", functionName[3:] + ": Sending New Data")
                    self.Cache[functionName[3:]] = eval("self." + functionName + "(wmi, payload)")

                    if(functionName[3:] == "Screenshot"): # For Screenshot
                        encMessage = self.Fernet.encrypt(self.Cache[functionName[3:]])   
                    else:
                        data["Request"] = payload # Pass request payload to response
                        data["Response"] = self.Cache[functionName[3:]]
                        encMessage = self.Fernet.encrypt(json.dumps(data).encode())
                    # Send all data on inital send
                    self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[3:] + "/Initial", encMessage, qos=1)
                        
                        
                    # Loop for periodic updates
                    while True:
                        time.sleep(1)
                        loopCount = loopCount + 1
                        if (loopCount == (60 * self.AgentSettings['Configurable']['Interval'][functionName])): # Every x minutes
                            loopCount = 0
                            # Get and send Data
                            New = eval("self." + functionName + "(wmi, payload)")
                            if(New != self.Cache[functionName[3:]]): # Only send data if diffrent.
                                result = diff(self.Cache[functionName[3:]], New)

                                self.log("Thread Loop", functionName[3:] + ": Sending New Data")
                                self.Cache[functionName[3:]] = New
                                data["Request"] = ""
                                data["Response"] = list(result)
                                encMessage = self.Fernet.encrypt(json.dumps(data).encode())
                                self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[3:] + "/Update", encMessage, qos=1)
  
                else: # This section is ran when asked to get data via a command
                    # Process Payload
                    try:
                        payload = json.loads(payload)
                    except Exception as e:
                        self.log("Thread", functionName + ": Warning cannot convert payload to JSON", e, "Warn")
                    
                    if(functionName not in self.lastRan): self.lastRan[functionName] = 0 
                    if(time.time() - self.lastRan[functionName] >= self.rateLimit or functionName in self.ignoreRateLimit):
                        self.lastRan[functionName] = time.time()
                        New = eval("self." + functionName + "(wmi, payload)")
                        self.log("Thread", functionName[3:] + ": Sending New Data")
                        result = diff(self.Cache[functionName[3:]], New)
                        self.Cache[functionName[3:]] = New

                        if(functionName[3:] == "Screenshot"): # For Screenshot
                            encMessage = self.Fernet.encrypt(self.Cache[functionName[3:]])
                            self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[3:] + "/Initial", encMessage, qos=1)
                        else:
                            data["Request"] = payload # Pass request payload to response
                            data["Response"] = list(result)
                            encMessage = self.Fernet.encrypt(json.dumps(data).encode())

                            self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[3:] + "/Update", encMessage, qos=1)
                    else: # Rate Limit Reached!
                        self.log("Thread", functionName[3:] + ": RATE LIMIT, Sending Cache")
                    

        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(DEBUG): print(traceback.format_exc())
            self.log("Thread "+ str(line_number) +" - " + functionName, e, "Error")

    # Set Agent Default Settings
    def setAgentDefaults(self):
        self.log("Start", "Setting Agent Default Settings")
        Interval = {}
        Interval["getHeartbeat"] = 1
        Interval["getAgentLog"] = 15
        Interval["getGeneral"] = 10
        Interval["getBIOS"] = 30
        Interval["getStartup"] = 30
        Interval["getOptionalFeatures"] = 30
        Interval["getProcesses"] = 30
        Interval["getServices"] = 30
        Interval["getUsers"] = 10
        Interval["getVideoConfiguration"] = 30
        Interval["getLogicalDisk"] = 20
        Interval["getMappedLogicalDisk"] = 30
        Interval["getPhysicalMemory"] = 15
        Interval["getPointingDevice"] = 30
        Interval["getKeyboard"] = 30
        Interval["getBaseBoard"] = 60
        Interval["getDesktopMonitor"] = 30
        Interval["getPrinters"] = 30
        Interval["getNetworkLoginProfile"] = 30
        Interval["getNetworkAdapters"] = 15
        Interval["getPnPEntities"] = 60
        Interval["getSoundDevices"] = 60
        Interval["getSCSIController"] = 120
        Interval["getProducts"] = 30
        Interval["getProcessor"] = 2
        Interval["getFirewall"] = 2
        Interval["getAgent"] = 180
        Interval["getBattery"] = 15
        Interval["getFilesystem"] = 30
        Interval["getSharedDrives"] = 30
        Interval["getEventLogs"] = 60
        Interval["getWindowsUpdates"] = 1440
        Interval["getScreenshot"] = 60
        Interval["getEventLog_Application"] = 60
        Interval["getEventLog_System"] = 60
        Interval["getEventLog_Setup"] = 60
        Interval["getEventLog_Security"] = 60
        
        self.AgentSettings['Configurable'] = {'Interval': Interval}
    
    # Set Agent Settings, 315/Commands/setAgentSettings, {"Interval": {"getFilesystem": 30, "getBattery": 30}}
    def setAgentSettings(self, wmi, payload=None):
        self.log("MQTT", "Got Agent Settings")
        try:
            self.AgentSettings['Configurable'] = json.loads(payload["data"])        
        except Exception as e:
            self.log("setAgentSettings", e, "Error")

    # Show Alert
    def setAlert(self, wmi, payload=None):
        try:
            response = ""
            if("data" in payload and "Type" in payload["data"] and "Message" in payload["data"] and "Title" in payload["data"]):
                if(payload["data"]["Type"] == "alert"): response = pyautogui.alert(payload["data"]["Message"], payload["data"]["Title"], 'Okay')
                if(payload["data"]["Type"] == "confirm"): response = pyautogui.confirm(payload["data"]["Message"], payload["data"]["Title"], ['Yes', 'No'])
                if(payload["data"]["Type"] == "prompt"): response = pyautogui.prompt(payload["data"]["Message"], payload["data"]["Title"], '')
                if(payload["data"]["Type"] == "password"): response = pyautogui.password(payload["data"]["Message"], payload["data"]["Title"], '', mask='*')
            return response
            self.log("Alert", "Sending Alert Response: " + response)
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("setAlert", e, "Error")

    # Send Keys
    def setKeyboard(self, wmi, payload=None):
        try:
            if("data" in payload):
                time.sleep(0.5)
                pyautogui.FAILSAFE = True
                pyautogui.write(payload["data"])
                self.log("setKeyboard", "Sending Keyboard Keys")
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("setKeyboard", e, "Error")

    # Heartbeat
    def getHeartbeat(self, wmi, payload=None):
        return time.time()

    # Agent Log
    def getAgentLog(self, wmi, payload=None):
        try:
            # Run Cleanup
            logRetention = 7
            logs = []
            count = 0
            d1 = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
            for log in self.AgentLog:
                d2 = datetime.datetime.strptime(log["Time"], "%Y-%m-%d %H:%M:%S.%f")
                if(( d1 - d2).days > logRetention):
                    count = count +1
                else:
                    logs.append(log)
            if(count > 0):
                print("Removed " + str(count) + " log entrys, they were " + str((d1 - d2).days) + " days old.")
            self.AgentLog = logs
            return self.AgentLog
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
        
    # Get Windows Update
    def getWindowsUpdates(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            data = {}
            count = -1
            for s in wmi.Win32_QuickFixEngineering(["Caption", "CSName", "Description", "FixComments", "HotFixID", "InstalledBy", "InstalledOn", "Status"]):     
                subWindowsUpdates = {}
                count = count +1
                subWindowsUpdates["Caption"] = s.Caption
                subWindowsUpdates["CSName"] = s.CSName
                subWindowsUpdates["Description"] = s.Description
                subWindowsUpdates["FixComments"] = s.FixComments
                subWindowsUpdates["HotFixID"] = s.HotFixID
                subWindowsUpdates["InstalledBy"] = s.InstalledBy
                subWindowsUpdates["InstalledOn"] = s.InstalledOn
                subWindowsUpdates["Status"] = s.Status
                data[str(count)] = subWindowsUpdates
                return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("GetWindowsUpdates", e, "Error")

    # Get Agent Settings
    def getAgentSettings(self, wmi, payload=None):
        return self.AgentSettings['Configurable']

    # Windows Activation
    def getWindowsActivation(self, wmi, payload=None):
        try:    
            data = {}
            licenseStatus = {}
            returnData = subprocess.check_output('cscript //nologo "%systemroot%\system32\slmgr.vbs" /dli', shell=True).decode()
            returnData = returnData.split('\r\n')
            licenseStatus["Name"] = returnData[1].split(": ")[1]
            licenseStatus["Description"] = returnData[2].split(": ")[1]
            licenseStatus["PartialProductKey"] = returnData[3].split(": ")[1]
            licenseStatus["LicenseStatus"] = returnData[4].split(": ")[1]
            licenseStatus["NotificationReason"] = returnData[5].split(": ")[1]
            data[0] = licenseStatus
            return data
        except Exception as e:
            print(traceback.format_exc())
            self.log("WindowsActivation", e, "Error")

    # Get General
    def getGeneral(self, wmi, payload=None):
        try:
            data = {}
            subGeneral = {}

            # Get Public IP Info
            IPInfo = urllib.request.urlopen('http://ipinfo.io/json').read().decode('utf8')
            subGeneral["ExternalIP"] = json.loads(IPInfo)

            # Get Local IP Info
            st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:       
                st.connect(('10.255.255.255', 1))
                subGeneral["PrimaryLocalIP"] = str(st.getsockname()[0])
            except Exception:
                subGeneral["PrimaryLocalIP"] = '127.0.0.1'
            finally:
                st.close()

            # Get Antivirus
            objWMI = GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiVirusProduct')
            for obj in objWMI:
                subGeneral["Antivirus"] = str(obj.displayName)

            wmi = wmi.WMI()
            for s in wmi.Win32_OperatingSystem(["BuildNumber", "Version", "csname", "FreePhysicalMemory", "LastBootUpTime", "Caption", "OSArchitecture", "SerialNumber", "NumberOfUsers", "NumberOfProcesses", "InstallDate", "Description"]):     
                subGeneral["Version"] = s.Version
                subGeneral["csname"] = s.csname
                subGeneral["FreePhysicalMemory"] = s.FreePhysicalMemory
                subGeneral["LastBootUpTime"] = s.LastBootUpTime
                subGeneral["Caption"] = s.Caption
                subGeneral["OSArchitecture"] = s.OSArchitecture
                subGeneral["SerialNumber"] = s.SerialNumber
                subGeneral["NumberOfUsers"] = s.NumberOfUsers
                subGeneral["NumberOfProcesses"] = s.NumberOfProcesses
                subGeneral["InstallDate"] = s.InstallDate
                subGeneral["Description"] = s.Description
                subGeneral["BuildNumber"] = s.BuildNumber
                
            for s in wmi.Win32_ComputerSystem(["manufacturer", "model", "systemtype", "totalphysicalmemory", "Domain", "HypervisorPresent", "NumberOfLogicalProcessors", "NumberOfProcessors", "Workgroup", "UserName"]):
                subGeneral["Manufacturer"] = s.manufacturer
                subGeneral["Model"] = s.model
                subGeneral["SystemType"] = s.systemtype
                subGeneral["Totalphysicalmemory"] = s.totalphysicalmemory
                subGeneral["Domain"] = s.Domain
                subGeneral["HypervisorPresent"] = s.HypervisorPresent
                subGeneral["NumberOfLogicalProcessors"] = s.NumberOfLogicalProcessors
                subGeneral["NumberOfProcessors"] = s.NumberOfProcessors
                subGeneral["Workgroup"] = s.Workgroup
                subGeneral["UserName"] = s.UserName

            data["0"] = subGeneral
            return data
        except Exception as e:
            print(traceback.format_exc())
            self.log("General", e, "Error")

    # Get Services
    def getServices(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Service(["Caption", "Description", "Status", "DisplayName", "State", "StartMode"]):
                count = count +1
                subService = {}
                subService["Description"] = s.Description
                subService["Status"] = s.Status
                subService["DisplayName"] = s.DisplayName 
                subService["State"] = s.State
                subService["StartMode"] = s.StartMode
                subService["Caption"] = s.Caption
                data[str(count)] = subService
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Services", e, "Error")

    # Get BIOS
    def getBIOS(self, wmi, payload=None):  
        try:
            wmi = wmi.WMI()
            data = {}
            for s in wmi.Win32_BIOS(["Caption", "Description", "Manufacturer", "Name", "SerialNumber", "Version", "Status"]):
                subBIOS = {}
                subBIOS["Caption"] = s.Caption
                subBIOS["Description"] = s.Description
                subBIOS["Manufacturer"] = s.Manufacturer
                subBIOS["Name"] = s.Name
                subBIOS["SerialNumber"] = s.SerialNumber
                subBIOS["Version"] = s.Version
                subBIOS["Status"] = s.Status
                data[0] = subBIOS
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("BIOS", e, "Error")         

    # Get Startup Items
    def getStartup(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_StartupCommand(["Caption", "Command", "Location"]):
                count = count +1
                subStartup = {}
                subStartup["Location"] = s.Location
                subStartup["Command"] = s.Command
                subStartup["Caption"] = s.Caption     
                data[str(count)] = subStartup
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Startup", e, "Error")      

    # Get Optional Features
    def getOptionalFeatures(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            data = {}
            count = -1
            for s in wmi.Win32_OptionalFeature(["Caption", "Description", "InstallDate", "Status", "Name", "InstallState"]):
                count = count +1
                subOptionalFeatures = {}
                subOptionalFeatures["Description"] = s.Description
                subOptionalFeatures["InstallDate"] = s.InstallDate
                subOptionalFeatures["Status"] = s.Status
                subOptionalFeatures["Name"] = s.Name
                subOptionalFeatures["Caption"] = s.Caption
                subOptionalFeatures["InstallState"] = s.InstallState
                data[str(count)] = subOptionalFeatures
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("OptionalFeatures", e, "Error")

    # Get Processes
    def getProcesses(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Process(["Caption", "Description", "ParentProcessId", "ProcessId", "Status", "Name"]):
                count = count +1
                subProcesses = {}
                subProcesses["Description"] = s.Description
                subProcesses["ParentProcessId"] = s.ParentProcessId
                subProcesses["PID"] = s.ProcessId
                subProcesses["Status"] = s.Status
                subProcesses["Name"] = s.Name
                subProcesses["Caption"] = s.Caption
                data[s.Caption] = subProcesses
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Processes", e, "Error")

    # Get User Accounts
    def getUsers(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_UserAccount(["Caption", "Description", "AccountType", "Disabled", "Domain", "FullName", "LocalAccount", "PasswordChangeable", "PasswordExpires", "PasswordRequired", "Name"]):
                count = count +1
                subUserAccounts = {}
                subUserAccounts["Description"] = s.Description
                subUserAccounts["AccountType"] = s.AccountType
                subUserAccounts["Disabled"] = s.Disabled
                subUserAccounts["Domain"] = s.Domain
                subUserAccounts["FullName"] = s.FullName
                subUserAccounts["LocalAccount"] = s.LocalAccount
                subUserAccounts["PasswordChangeable"] = s.PasswordChangeable
                subUserAccounts["PasswordExpires"] = s.PasswordExpires
                subUserAccounts["PasswordRequired"] = s.PasswordRequired
                subUserAccounts["Caption"] = s.Caption
                subUserAccounts["Name"] = s.Name 
                data[str(count)] = subUserAccounts
            return data         
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("UserAccounts", e, "Error")

    # Get Video Configuration
    def getVideoConfiguration(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_VideoConfiguration(["Caption", "Description", "AdapterChipType", "AdapterCompatibility", "AdapterDescription", "HorizontalResolution", "MonitorManufacturer", "MonitorType", "Name", "ScreenHeight", "ScreenWidth", "VerticalResolution"]):
                count = count +1
                subVideoConfiguration = {}
                subVideoConfiguration["AdapterChipType"] = s.AdapterChipType
                subVideoConfiguration["AdapterCompatibility"] = s.AdapterCompatibility
                subVideoConfiguration["AdapterDescription"] = s.AdapterDescription
                subVideoConfiguration["HorizontalResolution"] = s.HorizontalResolution
                subVideoConfiguration["MonitorManufacturer"] = s.MonitorManufacturer
                subVideoConfiguration["MonitorType"] = s.MonitorType
                subVideoConfiguration["Name"] = s.Name
                subVideoConfiguration["ScreenHeight"] = s.ScreenHeight
                subVideoConfiguration["ScreenWidth"] = s.ScreenWidth
                subVideoConfiguration["VerticalResolution"] = s.VerticalResolution
                subVideoConfiguration["Caption"] = s.Caption
                data[str(count)] = subVideoConfiguration
            return data            
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("VideoConfiguration", e, "Error")

    # Get Logical Disk
    def getLogicalDisk(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_LogicalDisk(["Description", "Name", "ProviderName", "Status", "VolumeName", "VolumeSerialNumber", "FileSystem", "DeviceID", "Caption", "PNPDeviceID", "Compressed", "FreeSpace", "Size", "VolumeSerialNumber"]):
                count = count +1
                subLogicalDisk = {}
                subLogicalDisk["Description"] = s.Description
                subLogicalDisk["Name"] = s.Name
                subLogicalDisk["ProviderName"] = s.ProviderName
                subLogicalDisk["Status"] = s.Status
                subLogicalDisk["VolumeName"] = s.VolumeName
                subLogicalDisk["FileSystem"] = s.FileSystem
                subLogicalDisk["DeviceID"] = s.DeviceID
                subLogicalDisk["PNPDeviceID"] = s.PNPDeviceID
                subLogicalDisk["Compressed"] = s.Compressed
                subLogicalDisk["FreeSpace"] = s.FreeSpace
                subLogicalDisk["Size"] = s.Size
                subLogicalDisk["VolumeSerialNumber"] = s.VolumeSerialNumber
                subLogicalDisk["Caption"] = s.Caption 
                data[str(count)] = subLogicalDisk
            return data 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("LogicalDisk", e, "Error")

    # Get Mapped Logical Disk
    def getMappedLogicalDisk(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_MappedLogicalDisk(["Caption", "Compressed", "Description", "FileSystem", "FreeSpace", "Name", "PNPDeviceID", "ProviderName", "Size", "Status", "SystemName", "VolumeName", "VolumeSerialNumber"]):
                count = count +1 
                subMappedLogicalDisk = {}
                subMappedLogicalDisk["Compressed"] = s.Compressed
                subMappedLogicalDisk["Description"] = s.Description
                subMappedLogicalDisk["FileSystem"] = s.FileSystem
                subMappedLogicalDisk["FreeSpace"] = s.FreeSpace
                subMappedLogicalDisk["Name"] = s.Name
                subMappedLogicalDisk["PNPDeviceID"] = s.PNPDeviceID
                subMappedLogicalDisk["ProviderName"] = s.ProviderName
                subMappedLogicalDisk["Size"] = s.Size
                subMappedLogicalDisk["Status"] = s.Status
                subMappedLogicalDisk["SystemName"] = s.SystemName
                subMappedLogicalDisk["VolumeName"] = s.VolumeName
                subMappedLogicalDisk["VolumeSerialNumber"] = s.VolumeSerialNumber
                subMappedLogicalDisk["Caption"] = s.Caption
                data[str(count)] = subMappedLogicalDisk
            return data 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("MappedLogicalDisk", e, "Error")

    # Get Physical Memory
    def getPhysicalMemory(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_PhysicalMemory(["BankLabel", "Capacity", "ConfiguredClockSpeed", "Description", "DeviceLocator", "FormFactor", "Manufacturer", "MemoryType", "Model", "Name", "PartNumber", "PositionInRow", "Speed", "Status"]):
                count = count +1
                subPhysicalMemory = {}
                subPhysicalMemory["BankLabel"] = s.BankLabel
                subPhysicalMemory["Capacity"] = s.Capacity
                subPhysicalMemory["ConfiguredClockSpeed"] = s.ConfiguredClockSpeed
                subPhysicalMemory["Description"] = s.Description
                subPhysicalMemory["DeviceLocator"] = s.DeviceLocator
                subPhysicalMemory["FormFactor"] = s.FormFactor
                subPhysicalMemory["Manufacturer"] = s.Manufacturer
                subPhysicalMemory["MemoryType"] = s.MemoryType
                subPhysicalMemory["Model"] = s.Model
                subPhysicalMemory["Name"] = s.Name
                subPhysicalMemory["PartNumber"] = s.PartNumber
                subPhysicalMemory["PositionInRow"] = s.PositionInRow
                subPhysicalMemory["Speed"] = s.Speed
                subPhysicalMemory["Status"] = s.Status
                data[str(count)] = subPhysicalMemory
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("PhysicalMemory", e, "Error")

    # Get Pointing Device
    def getPointingDevice(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_PointingDevice(["Caption", "Description", "DeviceID", "Manufacturer", "Name", "Status"]):
                count = count +1
                subPointingDevice = {}
                subPointingDevice["Caption"] = s.Caption
                subPointingDevice["Description"] = s.Description
                subPointingDevice["DeviceID"] = s.DeviceID
                subPointingDevice["Manufacturer"] = s.Manufacturer
                subPointingDevice["Name"] = s.Name
                subPointingDevice["Status"] = s.Status
                data[str(count)] = subPointingDevice
            return data 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("PointingDevice", e, "Error")

    # Get Keyboard
    def getKeyboard(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Keyboard(["Caption", "Description", "DeviceID", "Name", "Status"]):
                count = count +1
                subKeyboard = {}
                subKeyboard["Caption"] = s.Caption
                subKeyboard["Description"] = s.Description
                subKeyboard["DeviceID"] = s.DeviceID
                subKeyboard["Name"] = s.Name
                subKeyboard["Status"] = s.Status
                data[str(count)] = subKeyboard
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Keyboard", e, "Error")

    # Get BaseBoard
    def getBaseBoard(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_BaseBoard(["Caption", "Description", "Manufacturer", "Model", "Name", "Product", "SerialNumber", "Status", "Tag", "Version"]):
                count = count +1
                subBaseBoard = {}
                subBaseBoard["Caption"] = s.Caption
                subBaseBoard["Description"] = s.Description
                subBaseBoard["Manufacturer"] = s.Manufacturer
                subBaseBoard["Model"] = s.Model
                subBaseBoard["Name"] = s.Name
                subBaseBoard["Product"] = s.Product
                subBaseBoard["SerialNumber"] = s.SerialNumber
                subBaseBoard["Status"] = s.Status
                subBaseBoard["Tag"] = s.Tag
                subBaseBoard["Version"] = s.Version
                data[str(count)] = subBaseBoard
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("BaseBoard", e, "Error")

    # Get Desktop Monitor
    def getDesktopMonitor(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_DesktopMonitor(["Caption", "Description", "DeviceID", "MonitorManufacturer", "MonitorType", "Name", "Status", "ScreenHeight", "ScreenWidth"]):
                count = count +1
                subDesktopMonitor = {}
                subDesktopMonitor["Caption"] = s.Caption
                subDesktopMonitor["Description"] = s.Description
                subDesktopMonitor["DeviceID"] = s.DeviceID
                subDesktopMonitor["MonitorManufacturer"] = s.MonitorManufacturer
                subDesktopMonitor["MonitorType"] = s.MonitorType
                subDesktopMonitor["Name"] = s.Name
                subDesktopMonitor["Status"] = s.Status
                subDesktopMonitor["ScreenHeight"] = s.ScreenHeight
                subDesktopMonitor["ScreenWidth"] = s.ScreenWidth
                data[str(count)] = subDesktopMonitor
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("DesktopMonitor", e, "Error")

    # Get Printers
    def getPrinters(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Printer(["Caption", "Description", "Default", "DeviceID", "DriverName", "Local", "Name", "Network", "PortName", "Shared"]):
                count = count +1
                subPrinter = {}
                subPrinter["Caption"] = s.Caption
                subPrinter["Description"] = s.Description
                subPrinter["Default"] = s.Default
                subPrinter["DeviceID"] = s.DeviceID
                subPrinter["DriverName"] = s.DriverName
                subPrinter["Local"] = s.Local
                subPrinter["Name"] = s.Name
                subPrinter["Network"] = s.Network
                subPrinter["PortName"] = s.PortName
                subPrinter["Shared"] = s.Shared
                data[str(count)] = subPrinter
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Printers", e, "Error")
    
    # Get NetworkLoginProfile
    def getNetworkLoginProfile(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_NetworkLoginProfile(["Caption", "Description", "FullName", "HomeDirectory", "Name", "NumberOfLogons"]):
                count = count +1
                subNetworkLoginProfile = {}
                subNetworkLoginProfile["Caption"] = s.Caption
                subNetworkLoginProfile["Description"] = s.Description
                subNetworkLoginProfile["FullName"] = s.FullName
                subNetworkLoginProfile["HomeDirectory"] = s.HomeDirectory
                subNetworkLoginProfile["Name"] = s.Name
                subNetworkLoginProfile["NumberOfLogons"] = s.NumberOfLogons
                data[str(count)] = subNetworkLoginProfile
            return data    
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("NetworkLoginProfile", e, "Error")

    # Get Network Adapters
    def getNetworkAdapters(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_NetworkAdapterConfiguration(["Caption", "Description", "DHCPEnabled", "DHCPLeaseExpires", "DHCPLeaseObtained", "DHCPServer", "DNSDomain", "MACAddress", "Index", "IPAddress"], IPEnabled=1):
                count = count +1
                subNetworkAdapter = {}
                subNetworkAdapter["Caption"] = s.Caption
                subNetworkAdapter["Description"] = s.Description
                subNetworkAdapter["DHCPEnabled"] = s.DHCPEnabled
                subNetworkAdapter["DHCPLeaseExpires"] = s.DHCPLeaseExpires
                subNetworkAdapter["DHCPLeaseObtained"] = s.DHCPLeaseObtained
                subNetworkAdapter["DHCPServer"] = s.DHCPServer
                subNetworkAdapter["DNSDomain"] = s.DNSDomain
                subNetworkAdapter["Index"] = s.Index
                subNetworkAdapter["MACAddress"] = s.MACAddress
                data[str(count)] = subNetworkAdapter
            # Only publish if changed
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("NetworkAdapters", e, "Error")

    # Get PnP Entities
    def getPnPEntities(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_PnPEntity(["Caption", "Description", "DeviceID", "Manufacturer", "Name", "PNPClass", "PNPDeviceID", "Present", "Service", "Status"]):
                count = count +1
                subPnPEntity = {}
                subPnPEntity["Caption"] = s.Caption
                subPnPEntity["Description"] = s.Description
                subPnPEntity["DeviceID"] = s.DeviceID
                subPnPEntity["Manufacturer"] = s.Manufacturer
                subPnPEntity["Name"] = s.Name
                subPnPEntity["PNPClass"] = s.PNPClass
                subPnPEntity["PNPDeviceID"] = s.PNPDeviceID
                subPnPEntity["Present"] = s.Present
                subPnPEntity["Service"] = s.Service
                subPnPEntity["Status"] = s.Status
                data[str(count)] = subPnPEntity
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("PnPEntities", e, "Error")

    # Get Sound Entitys
    def getSoundDevices(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_SoundDevice(["Caption", "Description", "DeviceID", "Manufacturer", "Name", "ProductName", "Status"]):
                count = count +1
                subSoundDevice = {}
                subSoundDevice["Caption"] = s.Caption
                subSoundDevice["Description"] = s.Description
                subSoundDevice["DeviceID"] = s.DeviceID
                subSoundDevice["Manufacturer"] = s.Manufacturer
                subSoundDevice["Name"] = s.Name
                subSoundDevice["ProductName"] = s.ProductName
                subSoundDevice["Status"] = s.Status
                data[str(count)] = subSoundDevice
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("SoundDevices", e, "Error")

    # Get SCSI Controller
    def getSCSIController(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_SCSIController(["Caption", "Description", "DeviceID", "Manufacturer", "Name", "DriverName"]):
                count = count +1
                subSCSIController = {}
                subSCSIController["Caption"] = s.Caption
                subSCSIController["Description"] = s.Description
                subSCSIController["DeviceID"] = s.DeviceID
                subSCSIController["Manufacturer"] = s.Manufacturer
                subSCSIController["Name"] = s.Name
                subSCSIController["DriverName"] = s.DriverName
                data[str(count)] = subSCSIController
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("SCSIController", e, "Error")

    # Get Products
    def getProducts(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Product(["Caption", "Description", "IdentifyingNumber", "InstallLocation", "InstallState", "Name", "Vendor", "Version"]):
                count = count +1
                subProduct = {}
                subProduct["Caption"] = s.Caption
                subProduct["Description"] = s.Description
                subProduct["IdentifyingNumber"] = s.IdentifyingNumber
                subProduct["InstallLocation"] = s.InstallLocation
                subProduct["InstallState"] = s.InstallState
                subProduct["Name"] = s.Name
                subProduct["Vendor"] = s.Vendor
                subProduct["Version"] = s.Version      
                data[str(count)] = subProduct
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Products", e, "Error")

    # Get Processor
    def getProcessor(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Processor(["Caption", "CpuStatus", "CurrentClockSpeed", "CurrentVoltage", "Description", "DeviceID", "Manufacturer", "MaxClockSpeed", "Name", "NumberOfCores", "NumberOfLogicalProcessors", "SerialNumber", "ThreadCount", "Version", "LoadPercentage"]):
                count = count +1
                subProcessor = {}
                subProcessor["Caption"] = s.Caption
                subProcessor["CpuStatus"] = s.CpuStatus
                subProcessor["CurrentClockSpeed"] = s.CurrentClockSpeed
                subProcessor["CurrentVoltage"] = s.CurrentVoltage
                subProcessor["Description"] = s.Description
                subProcessor["DeviceID"] = s.DeviceID
                subProcessor["Manufacturer"] = s.Manufacturer
                subProcessor["MaxClockSpeed"] = s.MaxClockSpeed
                subProcessor["Name"] = s.Name
                subProcessor["NumberOfCores"] = s.NumberOfCores
                subProcessor["NumberOfLogicalProcessors"] = s.NumberOfLogicalProcessors
                subProcessor["SerialNumber"] = s.SerialNumber
                subProcessor["ThreadCount"] = s.ThreadCount
                subProcessor["Version"] = s.Version
                subProcessor["LoadPercentage"] = s.LoadPercentage
                data[str(count)] = subProcessor
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Processor", e, "Error")

    # Get Firewall
    def getFirewall(self, wmi, payload=None):
        try:
            data = {}
            subFirewall = {}
            subFirewall['currentProfile'] = 'ON' if "ON" in subprocess.check_output('netsh advfirewall show currentprofile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['publicProfile'] = 'ON' if "ON" in subprocess.check_output('netsh advfirewall show publicProfile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['privateProfile'] = 'ON' if "ON" in subprocess.check_output('netsh advfirewall show privateProfile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['domainProfile'] = 'ON' if "ON" in subprocess.check_output('netsh advfirewall show domainProfile state', shell=True).decode("utf-8") else 'OFF'
            data["0"] = subFirewall
            return data  
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Firewall", e, "Error")

    # Get Agent
    def getAgent(self, wmi, payload=None):
        try:
            data = {}
            subAgent = {}
            subAgent["Name"] = Service_Name
            subAgent["Version"] = Agent_Version
            subAgent["Path"] = os.path.dirname(os.path.abspath(__file__))
            data["0"] = subAgent
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Agent", e, "Error")

    # Get Battery
    def getBattery(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Battery(["Caption", "Description", "DeviceID", "EstimatedChargeRemaining", "EstimatedRunTime", "ExpectedBatteryLife", "ExpectedLife", "FullChargeCapacity", "MaxRechargeTime", "Name", "PNPDeviceID", "SmartBatteryVersion", "Status", "TimeOnBattery", "TimeToFullCharge", "BatteryStatus"]):
                count = count +1
                subBattery = {}
                subBattery["Caption"] = s.Caption
                subBattery["Description"] = s.Description
                subBattery["DeviceID"] = s.DeviceID
                subBattery["EstimatedChargeRemaining"] = str(s.EstimatedChargeRemaining)
                subBattery["EstimatedRunTime"] = str(s.EstimatedRunTime)
                subBattery["ExpectedBatteryLife"] = str(s.ExpectedBatteryLife)
                subBattery["ExpectedLife"] = str(s.ExpectedLife)
                subBattery["FullChargeCapacity"] = str(s.FullChargeCapacity)
                subBattery["MaxRechargeTime"] = str(s.MaxRechargeTime)
                subBattery["Name"] = s.Name
                subBattery["PNPDeviceID"] = s.PNPDeviceID
                subBattery["SmartBatteryVersion"] = s.SmartBatteryVersion
                subBattery["Status"] = s.Status
                subBattery["TimeOnBattery"] = str(s.TimeOnBattery)
                subBattery["TimeToFullCharge"] = str(s.TimeToFullCharge)
                subBattery["BatteryStatus"] = s.BatteryStatus
                data[str(count)] = subBattery
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Battery", e, "Error")

    # Get Filesystem
    def getFilesystem(self, wmi, payload=None):
        try:
            if("data" in payload):
                root = payload["data"]
                if(root == ""): root = "C://"
                self.log("getFilesystem", "Getting path: " + root)
                data = {}
                subFilesystem = []
                for item in os.listdir(root):
                    subFilesystem.append(os.path.join(root, item).replace("\\","/"))
                    data[0] = subFilesystem
                return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Filesystem", e, "Error")

    # Get Screenshot
    def getScreenshot(self, wmi, payload=None):
        try:
            screenshot = pyautogui.screenshot()
            screenshot = screenshot.resize((800,800), PIL.Image.ANTIALIAS)

            with io.BytesIO() as output:          
                screenshot.save(output, format='JPEG')
                data = output.getvalue()
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Screenshot", e, "Error")

    # Get Okla Speedtest
    def getOklaSpeedtest(self, wmi, payload=None):
        try:
            servers = []
            threads = None
            s = speedtest.Speedtest()
            s.get_servers(servers)
            s.get_best_server()
            s.download(threads=threads)
            s.upload(threads=threads)
            s.upload(pre_allocate=False)
            s.results.share()
            data = s.results.dict()
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("OklaSpeedtest", e, "Error")

    # Get Registry
    def getRegistry(self, wmi, payload=None):
        subRegistry = {}
        try:
            if("data" in payload):
                r = wmi.Registry()
                result, names = r.EnumKey(hDefKey=win32con.HKEY_LOCAL_MACHINE)
                for key in names:
                    print(key)
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("Registry", e, "Error")

    # Get Shared Drives
    def getSharedDrives(self, wmi, payload=None):
        subRegistry = {}
        wmi = wmi.WMI()
        try:
            count = -1
            data = {}
            for s in wmi.Win32_Share():
                count = count +1
                subSharedDrives = {}
                subSharedDrives["Name"] = s.Name
                subSharedDrives["Path"] = s.Path
                data[str(count)] = subSharedDrives
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("SharedDrives", e, "Error")

    # Get Event Logs
    def getEventLog_Application(self, wmi, payload=None): return self.getEventLogs(wmi, {"data":"Application"})
    def getEventLog_Security(self, wmi, payload=None): return self.getEventLogs(wmi, {"data":"Security"})
    def getEventLog_System(self, wmi, payload=None): return self.getEventLogs(wmi, {"data":"System"})
    def getEventLog_Setup(self, wmi, payload=None): return self.getEventLogs(wmi, {"data":"Setup"})

    def getEventLogs(self, wmi, payload=None):
        try:
            if("data" in payload):
                logType = payload["data"]
                if(logType == ""): logType = "System"
                if(logType=="System" or logType=="Security" or logType=="Application" or logType=="Setup"):
                    self.log("getEventLogs", "Getting " + logType + " Event Logs") 
                    events = self.EventLogSupport(logType)
                    count = 0
                    data = {}
                    for event in events:
                        count = count +1
                        data[str(count)] = event
                        if(count == 100): break
                    return data
                else:
                    self.log("getEventLogs", "Event Log Type not found in payload", "Warn")
            else:
                self.log("getEventLogs", "Event Log Type not found in payload", "Warn")
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("EventLogs", e, "Error")
        
    def EventLogSupport(self, logtype):
        # Get the event logs from the specified machine according to the
        # logtype (Example: Application) and return it

        hand = win32evtlog.OpenEventLog("localhost",logtype)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand,flags,0)
        evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'AUDIT_FAILURE',
                win32con.EVENTLOG_AUDIT_SUCCESS:'AUDIT_SUCCESS',
                win32con.EVENTLOG_INFORMATION_TYPE:'INFORMATION_TYPE',
                win32con.EVENTLOG_WARNING_TYPE:'WARNING_TYPE',
                win32con.EVENTLOG_ERROR_TYPE:'ERROR_TYPE'} 
        try:
            events = 1
            count = 0
            EventLog = []
            while events:
                events=win32evtlog.ReadEventLog(hand,flags,0)
                for ev_obj in events:
                    subEventLog = {}
                    the_time = ev_obj.TimeGenerated.Format() #'12/23/99 15:54:09'
                    evt_id = str(winerror.HRESULT_CODE(ev_obj.EventID))
                    computer = str(ev_obj.ComputerName)
                    cat = ev_obj.EventCategory
                    record = ev_obj.RecordNumber
                    msg = win32evtlogutil.SafeFormatMessage(ev_obj, logtype)
                    source = str(ev_obj.SourceName)
                    if not ev_obj.EventType in evt_dict.keys():
                        evt_type = "unknown"
                    else:
                        evt_type = str(evt_dict[ev_obj.EventType])
                    subEventLog["Time"] = the_time
                    subEventLog["ID"] = evt_id
                    subEventLog["Type"] = evt_type
                    subEventLog["Record"] = record
                    subEventLog["Source"] = source
                    subEventLog["Message"] = msg
                    EventLog.append(subEventLog)
            return EventLog
        except Exception as e:
            self.log("EventLogSupport", e, "Error")
                    
    # Run Code in CMD, Add Cache
    def CMD(self, payload):
        try:
            payload = json.loads(payload)
            if("data" in payload):
                command = payload["data"]
                self.log("CMD", "Running Command: " + command)
                data = str(subprocess.check_output(command, shell=True), "utf-8")
                return {"Request": payload, "Response": data} 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("CMD", e, "Error")

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OpenRMMAgent)

