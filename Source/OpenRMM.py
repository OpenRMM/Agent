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
Service_Name = "OpenRMMAgent"
Service_Display_Name = "OpenRMM Agent"
Service_Description = "A free open-source remote monitoring & management tool."

Agent_Version = "dev-2.0.4"

LOG_File = "C:\OpenRMM\Agent\Agent.log"
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
            self.AgentSettings = {}
            self.Cache = {}
            self.lastRan = {}
            self.AgentLog = []
            self.ignoreRateLimit = ["get_filesystem", "get_event_logs"]
            self.isrunning = True
            self.session_id = str(randint(1000000000000000, 1000000000000000000))
            self.MQTT_flag_connected = 0
            self.rateLimit = 120
            self.log("Setup", "Agent Starting")    

            try:
                if(exists("C:\OpenRMM.json")):
                    self.log("Setup", "Getting data from C:\OpenRMM.json")
                    f = open("C:\OpenRMM.json", "r")
                    self.AgentSettings = json.loads(f.read())
                else:
                    self.log("Read Config File", "Could not get data from file: C:\OpenRMM.json, file dont exist", "Error")
                    sys.stop()
            except Exception as e:
                self.log("Read Config File", e, "Error")
                sys.stop()

            try:
                self.log("Setup", "Starting MQTT")
                self.mqtt = mqtt.Client(client_id=self.session_id, clean_session=True)
                self.mqtt.username_pw_set(self.AgentSettings["MQTT"]["Username"], self.AgentSettings["MQTT"]["Password"])
                self.mqtt.will_set(self.session_id + "/Status", "0", qos=1, retain=True)
                self.mqtt.connect(self.AgentSettings["MQTT"]["Server"], port=self.AgentSettings["MQTT"]["Port"])
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
        self.log("MQTT", "Connected to server: " + self.AgentSettings["MQTT"]["Server"] + " with result code " + str(rc))
        if("Setup" not in self.AgentSettings):
            self.log("MQTT", "Sending New Agent command to server")
            self.mqtt.publish(self.session_id + "/Agent/New", "true", qos=1, retain=False)
        else:
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
            self.saveAgentSettings()
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
                    elif(command[2][0:4] == "get_" or command[2][0:4] == "set_"): 
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

        # Generate Salt
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
        if("Configurable" not in self.AgentSettings): self.setAgentDefaults()

        # Creating Threads
        if(self.MQTT_flag_connected == 1):
            self.log("Start", "Threads: Starting")
            self.threadHeartbeat = threading.Thread(target=self.startThread, args=["get_heartbeat", True]).start()
            self.threadAgentLog = threading.Thread(target=self.startThread, args=["get_agent_log", True]).start()
            self.threadGeneral = threading.Thread(target=self.startThread, args=["get_general", True]).start()
            self.threadBIOS = threading.Thread(target=self.startThread, args=["get_bios", True]).start()
            self.threadStartup = threading.Thread(target=self.startThread, args=["get_startup", True]).start()
            self.threadOptionalFeatures = threading.Thread(target=self.startThread, args=["get_optional_features", True]).start()
            self.threadProcesses = threading.Thread(target=self.startThread, args=["get_processes", True]).start()
            self.threadServices = threading.Thread(target=self.startThread, args=["get_services", True]).start()
            self.threadUserAccounts = threading.Thread(target=self.startThread, args=["get_users", True]).start()
            self.threadVideoConfiguration = threading.Thread(target=self.startThread, args=["get_video_configuration", True]).start()
            self.threadLogicalDisk = threading.Thread(target=self.startThread, args=["get_logical_disk", True]).start()
            self.threadMappedLogicalDisk = threading.Thread(target=self.startThread, args=["get_mapped_logical_disk", True]).start()
            self.threadPhysicalMemory = threading.Thread(target=self.startThread, args=["get_physical_memory", True]).start()
            self.threadPointingDevice = threading.Thread(target=self.startThread, args=["get_pointing_device", True]).start()
            self.threadKeyboard = threading.Thread(target=self.startThread, args=["get_keyboard", True]).start()
            self.threadBaseBoard = threading.Thread(target=self.startThread, args=["get_base_board", True]).start()
            self.threadDesktopMonitor = threading.Thread(target=self.startThread, args=["get_desktop_monitor", True]).start()
            self.threadPrinter = threading.Thread(target=self.startThread, args=["get_printers", True]).start()
            self.threadNetworkLoginProfile = threading.Thread(target=self.startThread, args=["get_network_login_profile", True]).start()
            self.threadNetworkAdapters = threading.Thread(target=self.startThread, args=["get_network_adapters", True]).start()
            self.threadPnPEntity = threading.Thread(target=self.startThread, args=["get_pnp_entities", True]).start()
            self.threadSoundDevice = threading.Thread(target=self.startThread, args=["get_sound_devices", True]).start()
            self.threadSCSIController = threading.Thread(target=self.startThread, args=["get_scsi_controller", True]).start()
            self.threadProduct = threading.Thread(target=self.startThread, args=["get_products", True]).start()
            self.threadProcessor = threading.Thread(target=self.startThread, args=["get_processor", True]).start()
            self.threadFirewall = threading.Thread(target=self.startThread, args=["get_firewall", True]).start()
            self.threadAgent = threading.Thread(target=self.startThread, args=["get_agent", True]).start()
            self.threadBattery = threading.Thread(target=self.startThread, args=["get_battery", True]).start()
            self.threadFilesystem = threading.Thread(target=self.startThread, args=["get_filesystem", True, {"data":"C:\\"}]).start()
            self.threadSharedDrives = threading.Thread(target=self.startThread, args=["get_shared_drives", True]).start()
            self.threadEventLogs_System = threading.Thread(target=self.startThread, args=["get_event_log_system", True]).start()
            self.threadEventLogs_Application = threading.Thread(target=self.startThread, args=["get_event_log_application", True]).start()
            self.threadEventLogs_Security = threading.Thread(target=self.startThread, args=["get_event_log_security", True]).start()
            self.threadEventLogs_Setup = threading.Thread(target=self.startThread, args=["get_event_log_setup", True]).start()
            self.threadScreenshot = threading.Thread(target=self.startThread, args=["get_screenshot", True]).start()
            
            # Send these only once on startup, unless an interval is defined by the front end
            self.threadRegistry = threading.Thread(target=self.startThread, args=["get_registry", True]).start()
            self.threadWindowsActivation = threading.Thread(target=self.startThread, args=["get_windows_activation", True]).start()
            self.threadAgentLog = threading.Thread(target=self.startThread, args=["get_agent_log", True]).start()
            self.threadAgentSettings = threading.Thread(target=self.startThread, args=["get_agent_settings", True]).start()
            # self.threadOklaSpeedtest = threading.Thread(target=self.startThread, args=["get_okla_speedtest", True]).start()

            self.log("Start", "Threads: Started")
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

    # Save Agent Settings to Json File
    def saveAgentSettings(self):
        # Save setup to File
        f = open("C:\OpenRMM.json", "w")
        f.write(json.dumps(self.AgentSettings))
        f.close()

    # Start Thread
    def startThread(self, functionName, loop=False, payload="{}"):
        try:
            if(self.MQTT_flag_connected == 1):
                pythoncom.CoInitialize()
                loopCount = 0
                data = {}
                # Set Default Value 
                if(functionName[4:] not in self.Cache): self.Cache[functionName[4:]] = ""

                # Send Data on Startup and on Threads
                if(loop == True and functionName[0:4] == "get_"):
                    self.log("Thread", functionName[4:] + ": Sending New Data")
                    New = eval("self." + functionName + "(wmi, payload)")
                    
                    if(functionName[4:] == "screenshot"):
                        encMessage = self.Fernet.encrypt(New)
                    else:
                        result = diff({}, New)
                        data["Request"] = payload # Pass request payload to response
                        data["Response"] = list(result)
                        encMessage = self.Fernet.encrypt(json.dumps(data).encode())
                    self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[4:] + "/Update", encMessage, qos=1)
                
                    # Loop for periodic updates
                    while functionName[4:] in self.AgentSettings['Configurable']['Interval']:
                        time.sleep(1)
                        loopCount = loopCount + 1
                        if (loopCount == (60 * self.AgentSettings['Configurable']['Interval'][functionName[4:]]) and self.AgentSettings['Configurable']['Interval'][functionName[4:]] != "0"): # Every x minutes
                            loopCount = 0
                            # Get and send Data
                            New = eval("self." + functionName + "(wmi, payload)")
                            if(New != self.Cache[functionName[4:]]): # Only send data if diffrent.
                                self.log("Thread Loop", functionName[4:] + ": Sending New Data")
                                
                                if(functionName[4:] == "screenshot"):
                                    encMessage = self.Fernet.encrypt(New)
                                    self.Cache[functionName[4:]] = New
                                else:
                                    result = diff(self.Cache[functionName[4:]], New)
                                    self.Cache[functionName[4:]] = New
                                    data["Request"] = ""
                                    data["Response"] = list(result)
                                    encMessage = self.Fernet.encrypt(json.dumps(data).encode())
                                self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[4:] + "/Update", encMessage, qos=1)
  
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
                        self.log("Thread", functionName[4:] + ": Sending New Data")                    

                        if(functionName[4:] == "screenshot"):
                            encMessage = self.Fernet.encrypt(New)
                            self.Cache[functionName[4:]] = New
                        else:
                            result = diff(self.Cache[functionName[4:]], New)
                            self.Cache[functionName[4:]] = New
                            data["Request"] = payload # Pass request payload to response
                            data["Response"] = list(result)
                            encMessage = self.Fernet.encrypt(json.dumps(data).encode())
                        self.mqtt.publish(str(self.AgentSettings["Setup"]["ID"]) + "/Data/" + functionName[4:] + "/Update", encMessage, qos=1)
                    else: # Rate Limit Reached!
                        self.log("Thread", functionName[4:] + ": RATE LIMIT")
                    
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            line_number = exception_traceback.tb_lineno
            if(DEBUG): print(traceback.format_exc())
            self.log("Thread "+ str(line_number) +" - " + functionName, e, "Error")

    # Set Agent Default Settings
    def setAgentDefaults(self):
        self.log("Start", "Setting Agent Default Settings")
        Interval = {}
        Interval["heartbeat"] = 1
        Interval["agent_log"] = 15
        Interval["general"] = 10
        Interval["bios"] = 30
        Interval["startup"] = 30
        Interval["optional_features"] = 30
        Interval["processes"] = 30
        Interval["services"] = 30
        Interval["users"] = 10
        Interval["video_configuration"] = 30
        Interval["logical_disk"] = 20
        Interval["mapped_logical_disk"] = 30
        Interval["physical_memory"] = 15
        Interval["pointing_device"] = 30
        Interval["keyboard"] = 30
        Interval["base_board"] = 60
        Interval["desktop_monitor"] = 30
        Interval["printers"] = 30
        Interval["network_login_profile"] = 30
        Interval["network_adapters"] = 15
        Interval["pnp_entities"] = 60
        Interval["sound_devices"] = 60
        Interval["scsi_controller"] = 120
        Interval["products"] = 30
        Interval["processor"] = 2
        Interval["firewall"] = 2
        Interval["agent"] = 180
        Interval["battery"] = 15
        Interval["filesystem"] = 30
        Interval["shared_drives"] = 30
        Interval["event_logs"] = 60
        Interval["windows_updates"] = 1440
        Interval["screenshot"] = 60
        Interval["event_log_application"] = 60
        Interval["event_log_system"] = 60
        Interval["event_log_setup"] = 60
        Interval["event_log_security"] = 60
        
        self.AgentSettings['Configurable'] = {'Interval': Interval}

    # Update the Agent
    def set_update_agent(self, wmi, payload=None):
        if("data" in payload):
            if("update_url" in payload["data"]):
                updateURL = payload['data']['update_url']
                self.log("Update Agent", "Update Requested")  
                proc = subprocess.Popen("start C:/OpenRMM/Agent/update.bat", shell=True)
                time.sleep(2)
                self.SvcStop()
            else:
                self.log("Update Agent", "Cannot update, missing update_url", "Warn")
        else:
            self.log("Update Agent", "Cannot update, missing data[update_url]", "Warn")

    # Set Agent Settings, 315/Commands/setAgentSettings, {"Interval": {"getFilesystem": 30, "getBattery": 30}}
    def set_agent_settings(self, wmi, payload=None):
        self.log("MQTT", "Got Agent Settings")
        try:
            self.AgentSettings['Configurable'] = {'Interval': payload["Interval"]}
            self.saveAgentSettings()      
        except Exception as e:
            self.log("set_agent_settings", e, "Error")

    # Show Alert
    def set_alert(self, wmi, payload=None):
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
            self.log("set_alert", e, "Error")

    # Send Keys
    def set_keyboard(self, wmi, payload=None):
        try:
            if("data" in payload):
                time.sleep(0.5)
                pyautogui.FAILSAFE = True
                pyautogui.write(payload["data"])
                self.log("setKeyboard", "Sending Keyboard Keys")
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("set_keyboard", e, "Error")

    # Heartbeat
    def get_heartbeat(self, wmi, payload=None):
        return time.time()

    # Agent Log
    def get_agent_log(self, wmi, payload=None):
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
    def get_windows_updates(self, wmi, payload=None):
        try:
            wmi = wmi.WMI()
            data = {}
            count = -1
            for s in wmi.Win32_QuickFixEngineering(["Caption", "CSName", "Description", "FixComments", "HotFixID", "InstalledBy", "InstalledOn", "Status"]):     
                subWindowsUpdates = {}
                count = count +1
                subWindowsUpdates["Caption"] = s.Caption
                subWindowsUpdates["CSName"] = s.CSName
                subWindowsUpdates["Description"] = s.D
                escription
                subWindowsUpdates["FixComments"] = s.FixComments
                subWindowsUpdates["HotFixID"] = s.HotFixID
                subWindowsUpdates["InstalledBy"] = s.InstalledBy
                subWindowsUpdates["InstalledOn"] = s.InstalledOn
                subWindowsUpdates["Status"] = s.Status
                data[s.Caption] = subWindowsUpdates
                return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("windows_updates", e, "Error")

    # Get Agent Settings
    def get_agent_settings(self, wmi, payload=None):
        return self.AgentSettings['Configurable']

    # Windows Activation
    def get_windows_activation(self, wmi, payload=None):
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
            data["0"] = licenseStatus
            return data
        except Exception as e:
            print(traceback.format_exc())
            self.log("windows_activation", e, "Error")

    # Get General
    def get_general(self, wmi, payload=None):
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
            if(DEBUG): print(traceback.format_exc())
            self.log("general", e, "Error")

    # Get Services
    def get_services(self, wmi, payload=None):
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
                data[s.Caption] = subService
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("services", e, "Error")

    # Get BIOS
    def get_bios(self, wmi, payload=None):  
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
                data["0"] = subBIOS
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("bios", e, "Error")         

    # Get Startup Items
    def get_startup(self, wmi, payload=None):
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
                data[s.Caption] = subStartup
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("startup", e, "Error")      

    # Get Optional Features
    def get_optional_features(self, wmi, payload=None):
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
                data[s.Caption] = subOptionalFeatures
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("optional_features", e, "Error")

    # Get Processes
    def get_processes(self, wmi, payload=None):
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
            self.log("processes", e, "Error")

    # Get User Accounts
    def get_users(self, wmi, payload=None):
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
                data[s.Caption] = subUserAccounts
            return data         
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("user_accounts", e, "Error")

    # Get Video Configuration
    def get_video_configuration(self, wmi, payload=None):
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
                data[s.Caption] = subVideoConfiguration
            return data            
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("video_configuration", e, "Error")

    # Get Logical Disk
    def get_logical_disk(self, wmi, payload=None):
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
                data[s.Caption] = subLogicalDisk
            return data 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("logical_disk", e, "Error")

    # Get Mapped Logical Disk
    def get_mapped_logical_disk(self, wmi, payload=None):
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
                data[s.Caption] = subMappedLogicalDisk
            return data 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("mapped_logical_disk", e, "Error")

    # Get Physical Memory
    def get_physical_memory(self, wmi, payload=None):
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
                data[s.Name] = subPhysicalMemory
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("physical_memory", e, "Error")

    # Get Pointing Device
    def get_pointing_device(self, wmi, payload=None):
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
                data[s.Caption] = subPointingDevice
            return data 
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("pointing_device", e, "Error")

    # Get Keyboard
    def get_keyboard(self, wmi, payload=None):
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
                data[s.Caption] = subKeyboard
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("keyboard", e, "Error")

    # Get BaseBoard
    def get_base_board(self, wmi, payload=None):
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
                data[s.Caption] = subBaseBoard
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("base_board", e, "Error")

    # Get Desktop Monitor
    def get_desktop_monitor(self, wmi, payload=None):
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
                data[s.Caption] = subDesktopMonitor
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("desktop_monitor", e, "Error")

    # Get Printers
    def get_printers(self, wmi, payload=None):
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
                data[s.Caption] = subPrinter
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("printers", e, "Error")
    
    # Get NetworkLoginProfile
    def get_network_login_profile(self, wmi, payload=None):
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
                data[s.Caption] = subNetworkLoginProfile
            return data    
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("network_login_profile", e, "Error")

    # Get Network Adapters
    def get_network_adapters(self, wmi, payload=None):
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
                data[s.Caption] = subNetworkAdapter
            # Only publish if changed
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("network_adapters", e, "Error")

    # Get PnP Entities
    def get_pnp_entities(self, wmi, payload=None):
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
                data[s.Caption] = subPnPEntity
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("pnp_entities", e, "Error")

    # Get Sound Entitys
    def get_sound_devices(self, wmi, payload=None):
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
                data[s.Caption] = subSoundDevice
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("sound_devices", e, "Error")

    # Get SCSI Controller
    def get_scsi_controller(self, wmi, payload=None):
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
                data[s.Caption] = subSCSIController
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("scsi_controller", e, "Error")

    # Get Products
    def get_products(self, wmi, payload=None):
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
                data[s.Caption] = subProduct
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("products", e, "Error")

    # Get Processor
    def get_processor(self, wmi, payload=None):
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
            self.log("processor", e, "Error")

    # Get Firewall
    def get_firewall(self, wmi, payload=None):
        try:
            data = {}
            subFirewall = {}
            subFirewall['currentProfile'] = 'Enabled' if "ON" in subprocess.check_output('netsh advfirewall show currentprofile state', shell=True).decode("utf-8") else 'Disabled'
            subFirewall['publicProfile'] = 'Enabled' if "ON" in subprocess.check_output('netsh advfirewall show publicProfile state', shell=True).decode("utf-8") else 'Disabled'
            subFirewall['privateProfile'] = 'Enabled' if "ON" in subprocess.check_output('netsh advfirewall show privateProfile state', shell=True).decode("utf-8") else 'Disabled'
            subFirewall['domainProfile'] = 'Enabled' if "ON" in subprocess.check_output('netsh advfirewall show domainProfile state', shell=True).decode("utf-8") else 'Disabled'
            data["0"] = subFirewall
            return data  
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("firewall", e, "Error")

    # Get Agent
    def get_agent(self, wmi, payload=None):
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
            self.log("agent", e, "Error")

    # Get Battery
    def get_battery(self, wmi, payload=None):
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
                data[s.Caption] = subBattery
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("battery", e, "Error")

    # Get Filesystem
    def get_filesystem(self, wmi, payload=None):
        try:
            if("data" in payload):
                root = payload["data"]
                if(root == ""): root = "C://"
                self.log("getFilesystem", "Getting path: " + root)
                data = {}
                subFilesystem = []
                for item in os.listdir(root):
                    subFilesystem.append(os.path.join(root, item).replace("\\","/"))
                    data["0"] = subFilesystem
                return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("filesystem", e, "Error")

    # Get Screenshot
    def get_screenshot(self, wmi, payload=None):
        try:
            screenshot = pyautogui.screenshot()
            screenshot = screenshot.resize((800,800), PIL.Image.ANTIALIAS)

            with io.BytesIO() as output:          
                screenshot.save(output, format='JPEG')
                return output.getvalue()
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("screenshot", e, "Error")

    # Get Okla Speedtest
    def get_okla_speedtest(self, wmi, payload=None):
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
            self.log("okla_speedtest", e, "Error")

    # Get Registry
    def get_registry(self, wmi, payload=None):
        subRegistry = {}
        try:
            return subRegistry
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("registry", e, "Error")

    # Get Shared Drives
    def get_shared_drives(self, wmi, payload=None):
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
                data[s.Name] = subSharedDrives
            return data
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("shared_drives", e, "Error")

    # Get Event Logs
    def get_event_log_application(self, wmi, payload=None): return self.get_event_logs(wmi, {"data":"Application"})
    def get_event_log_security(self, wmi, payload=None): return self.get_event_logs(wmi, {"data":"Security"})
    def get_event_log_system(self, wmi, payload=None): return self.get_event_logs(wmi, {"data":"System"})
    def get_event_log_setup(self, wmi, payload=None): return self.get_event_logs(wmi, {"data":"Setup"})

    def get_event_logs(self, wmi, payload=None):
        try:
            if("data" in payload):
                logType = payload["data"]
                if(logType == ""): logType = "System"
                if(logType=="System" or logType=="Security" or logType=="Application" or logType=="Setup"):
                    self.log("event_logs", "Getting " + logType + " Event Logs") 
                    events = self.EventLogSupport(logType)
                    count = 0
                    data = {}
                    for event in events:
                        count = count +1
                        data[str(count)] = event
                        if(count == 100): break
                    return data
                else:
                    self.log("event_logs", "Event Log Type not found in payload", "Warn")
            else:
                self.log("event_logs", "Event Log Type not found in payload", "Warn")
        except Exception as e:
            if(DEBUG): print(traceback.format_exc())
            self.log("event_logs", e, "Error")
        
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

