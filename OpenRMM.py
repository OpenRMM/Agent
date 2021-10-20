#!/usr/bin/env python3

# TODo:
# Group, WindowsActivation

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
import speedtest
import traceback

################################# SETUP ##################################
MQTT_Server = "****"
MQTT_Username = "*****"
MQTT_Password = "***"
MQTT_Port = 1884

Service_Name = "OpenRMMAgent"
Service_Display_Name = "The OpenRMM Agent"
Service_Description = "A free open-source remote monitoring & management tool."

Agent_Version = "1.4"

LOG_File = "C:\OpenRMM.log"

###########################################################################

required = {'paho-mqtt', 'pyautogui', 'pywin32', 'wmi', 'pillow', 'scandir', 'speedtest-cli'}
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
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,servicemanager.PYS_SERVICE_STARTED,(self._svc_name_, ''))
        self.isrunning = True
        print("Starting Setup")
        self.hostname = os.environ['COMPUTERNAME']
        self.ID = 0
        self.MQTT_flag_connected = 0

        try:
            print("MQTT: Starting Setup")
            client_id = self.hostname + str(randint(1000, 10000))
            self.mqtt = mqtt.Client(client_id=client_id, clean_session=True)
            self.mqtt.username_pw_set(MQTT_Username, MQTT_Password)
            self.mqtt.connect(MQTT_Server, port=MQTT_Port)
            self.mqtt.subscribe(self.hostname + "/Commands/#", qos=1)
            self.mqtt.on_message = self.on_message
            self.mqtt.on_connect = self.on_connect
            self.mqtt.on_disconnect = self.on_disconnect
            self.mqtt.loop_start()
        except Exception as e:
            self.log("SetupMQTT", e)

        print("WMI: Starting Setup")
        pythoncom.CoInitialize()
        self.wmimain = wmi.WMI()
        self.rateLimit = 120
        self.lastRan = {}
        self.ignoreRateLimit = ["getFilesystem", "setAlert"]
        self.AgentSettings = {}
        self.Cache = {}

        print("Finished Setup")

        try:
            if(exists("C:\OpenRMM.json")):
                print("Getting data from C:\OpenRMM.json")
                f = open("C:\OpenRMM.json", "r")
                file = json.loads(f.read())
                self.ID = str(file["ID"])
                self.start()
            else:
                print("Could not get data from file: C:\OpenRMM.json, file dont exist")
        except Exception as e:
            self.log("SaveID", e)

        self.main()

    def stop(self):
        self.isrunning = False

    def main(self):
        while self.isrunning:
            time.sleep(0.1)

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, rc):
        self.MQTT_flag_connected = 1
        print("MQTT: Connected with result code " + str(rc))
        if(exists("C:\OpenRMM_ID.txt") == False):
            self.mqtt.publish(self.hostname + "/Setup", "true", qos=1, retain=False)

    def on_disconnect(self, xclient, userdata, rc):
        if rc != 0:
            print("MQTT: Unexpected disconnection")
            self.MQTT_flag_connected = 0

    def on_message(self, client, userdata, message):
        print("MQTT: Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))
        if (str(message.topic) == str(self.ID) + "/Commands/CMD"): self.CMD(message.payload)
        if (str(message.topic) == self.hostname + "/Commands/ID"):
            self.ID = str(message.payload, 'utf-8')
            print("Got ID From server, Setting Up Agent with ID: " + str(self.ID))
    
            # Save ID to File
            f = open("C:\OpenRMM.json", "w")
            file = {}
            file["ID"] = str(self.ID)
            file["Hostname"] = self.hostname
            f.write(json.dumps(file))
            f.close()
            self.start()

        try:
            # Process commands
            command = message.topic.split("/")
            if(command[1] == "Commands"):
                if(command[2][0:3] == "get" or command[2][0:3] == "set"): threading.Thread(target=self.startThread, args=[command[2], 1, message.payload.decode('utf-8')]).start()
                if(command[2] == "showAlert"): self.showAlert(self.command["payload"])
            self.command = {}
        except Exception as e:
            self.log("Commands", e)

    def start(self):
        print("This Computers ID is: " + str(self.ID))

        # Check if got agent settings here, if not load defaults
        self.mqtt.unsubscribe(self.hostname + "/Commands/#")
        self.mqtt.will_set(str(self.ID) + "/Status", "Offline", qos=1, retain=True)
        self.mqtt.subscribe(str(self.ID) + "/Commands/#", qos=1)
        self.mqtt.publish(str(self.ID) + "/Status", "Online", qos=1, retain=True)
        print("Waiting for Agent Settings")

        count = 0
        while (count <= 5):
            count = count + 1
            time.sleep(1)
            if(count == 5):
                if(self.AgentSettings == {}): self.setAgentDefaults()

        # Creating Threads
        if(self.MQTT_flag_connected == 1):
            print("Threads: Configuring")
            self.threadHeartbeat = threading.Thread(target=self.startThread, args=["Heartbeat"]) 
            self.threadGeneral = threading.Thread(target=self.startThread, args=["getGeneral"])
            self.threadBIOS = threading.Thread(target=self.startThread, args=["getBIOS"])
            self.threadStartup = threading.Thread(target=self.startThread, args=["getStartup"])
            self.threadOptionalFeatures = threading.Thread(target=self.startThread, args=["getOptionalFeatures"])
            self.threadProcesses = threading.Thread(target=self.startThread, args=["getProcesses"])
            self.threadServices = threading.Thread(target=self.startThread, args=["getServices"])
            self.threadUserAccounts = threading.Thread(target=self.startThread, args=["getUsers"])
            self.threadVideoConfiguration = threading.Thread(target=self.startThread, args=["getVideoConfiguration"])
            self.threadLogicalDisk = threading.Thread(target=self.startThread, args=["getLogicalDisk"])
            self.threadMappedLogicalDisk = threading.Thread(target=self.startThread, args=["getMappedLogicalDisk"])
            self.threadPhysicalMemory = threading.Thread(target=self.startThread, args=["getPhysicalMemory"])
            self.threadPointingDevice = threading.Thread(target=self.startThread, args=["getPointingDevice"])
            self.threadKeyboard = threading.Thread(target=self.startThread, args=["getKeyboard"])
            self.threadBaseBoard = threading.Thread(target=self.startThread, args=["getBaseBoard"])
            self.threadDesktopMonitor = threading.Thread(target=self.startThread, args=["getDesktopMonitor"])
            self.threadPrinter = threading.Thread(target=self.startThread, args=["getPrinters"])
            self.threadNetworkLoginProfile = threading.Thread(target=self.startThread, args=["getNetworkLoginProfile"])
            self.threadNetworkAdapters = threading.Thread(target=self.startThread, args=["getNetworkAdapters"])
            self.threadPnPEntity = threading.Thread(target=self.startThread, args=["getPnPEntitys"])
            self.threadSoundDevice = threading.Thread(target=self.startThread, args=["getSoundDevices"])
            self.threadSCSIController = threading.Thread(target=self.startThread, args=["getSCSIController"])
            self.threadProduct = threading.Thread(target=self.startThread, args=["getProducts"])
            self.threadProcessor = threading.Thread(target=self.startThread, args=["getProcessor"])
            self.threadFirewall = threading.Thread(target=self.startThread, args=["getFirewall"])
            self.threadAgent = threading.Thread(target=self.startThread, args=["getAgent"])
            self.threadBattery = threading.Thread(target=self.startThread, args=["getBattery"])
            self.threadFilesystem = threading.Thread(target=self.startThread, args=["getFilesystem"]) 
            self.threadSharedDrives = threading.Thread(target=self.startThread, args=["getSharedDrives"])
            self.threadEventLogs_System = threading.Thread(target=self.startThread, args=["getEventLogs", 0, "System"])
            self.threadEventLogs_Application = threading.Thread(target=self.startThread, args=["getEventLogs", 0, "Application"])
            self.threadEventLogs_Security = threading.Thread(target=self.startThread, args=["getEventLogs", 0, "Security"])
            self.threadEventLogs_Setup = threading.Thread(target=self.startThread, args=["getEventLogs", 0, "Setup"])
            print("Threads: Finished Configuring")

            print("Threads: Starting All")
            self.threadHeartbeat.start()
            self.threadGeneral.start()
            self.threadBIOS.start()
            self.threadStartup.start()
            self.threadOptionalFeatures.start()
            self.threadProcesses.start()
            self.threadServices.start()
            self.threadUserAccounts.start()
            self.threadVideoConfiguration.start()
            self.threadLogicalDisk.start()
            self.threadMappedLogicalDisk.start()
            self.threadPhysicalMemory.start()
            self.threadPointingDevice.start()
            self.threadKeyboard.start()
            self.threadBaseBoard.start()
            self.threadDesktopMonitor.start()
            self.threadPrinter.start()
            self.threadNetworkLoginProfile.start()
            self.threadNetworkAdapters.start()
            self.threadPnPEntity.start()
            self.threadSoundDevice.start()
            self.threadSCSIController.start()
            self.threadProduct.start()
            self.threadProcessor.start()
            self.threadFirewall.start()
            self.threadAgent.start()
            self.threadBattery.start()
            self.threadFilesystem.start()
            self.threadSharedDrives.start()
            self.threadEventLogs_System.start()
            self.threadEventLogs_Application.start()
            self.threadEventLogs_Security.start()
            self.threadEventLogs_Setup.start()
            print("Threads: Finished Starting")     
        else:
            print("Start: MQTT is not connected")   

    # Log
    def log(self, name, message):
        print("Error in: " + name)
        print(message)
        try:
            f = open(LOG_File, "a")
            f.write("Error in: " + str(name) + ": " + str(message) + "\n")
            f.close()
        except Exception as e:
            print("Error saving to log file")
            print(e)

    # Start Thread
    def startThread(self, functionName, force=0, payload=""):
        try:
            print("Calling Function: " + functionName[3:])
            if(self.MQTT_flag_connected == 1):
                pythoncom.CoInitialize()
                loopCount = 0
                data = {}
                # Set Default Value 
                if(functionName[3:] not in self.Cache): self.Cache[functionName[3:]] = ""

                # Send Data on Startup and on Threads
                if(force == 0 and functionName[0:3] == "get" and functionName in self.AgentSettings['interval']):
                    # Get and Send Data on Startup
                    self.Cache[functionName[3:]] = eval("self." + functionName + "(wmi, False, payload)")

                    # Loop for periodic updates
                    while True:
                        time.sleep(1)
                        loopCount = loopCount + 1
                        if (loopCount == (60 * self.AgentSettings['interval'][functionName])): # Every x minutes
                            loopCount = 0
                            # Get and send Data
                            fresh = eval("self." + functionName + "(wmi, False, payload)")
                            if(fresh != self.Cache[functionName[3:]]): # Only send data if diffrent.
                                self.Cache[functionName[3:]] = fresh # Set Cache
                                data["Request"] = ""
                                data["Response"] = fresh
                                self.mqtt.publish(str(self.ID) + "/Data/" + functionName[3:], json.dumps(data), qos=1)
                else: # This section is ran when asked to get data via a command
                    # Process Payload
                    #payload = json.loads(payload)
                    #if("userID" in payload):
                    
                    if(functionName not in self.lastRan): self.lastRan[functionName] = 0 
                    if(time.time() - self.lastRan[functionName] >= self.rateLimit or functionName in self.ignoreRateLimit):
                        self.lastRan[functionName] = time.time()
                        self.Cache[functionName[3:]] = eval("self." + functionName + "(wmi, True, payload)")
                        print(functionName[3:] + ": Sending Fresh Data")
                    else: # Rate Limit Reached!
                        print(functionName[3:] + ": RATE LIMIT, Sending Cache")
                    
                if(functionName[3:] == "Screenshot"): # For Screenshot
                    self.mqtt.publish(str(self.ID) + "/Data/" + functionName[3:], self.Cache[functionName[3:]], qos=1)
                else:
                    data["Request"] = payload
                    data["Response"] = self.Cache[functionName[3:]]
                    #self.mqtt.publish(str(self.ID) + "/Data/" + functionName[3:], json.dumps(data), qos=1)
                    self.mqtt.publish(str(self.ID) + "/Data/" + functionName[3:], json.dumps(self.Cache[functionName[3:]]), qos=1)
        except Exception as e:
            self.log("StartThread", e)
            tb = traceback.format_exc()
            print(tb)

    # Set Agent Default Settings
    def setAgentDefaults(self):
        print("Setting Agent Default Settings")
        interval = {}
        interval["Heartbeat"] = 5
        interval["getGeneral"] = 30
        interval["getBIOS"] = 30
        interval["getStartup"] = 30
        interval["getOptionalFeatures"] = 30
        interval["getProcesses"] = 30
        interval["getServices"] = 30
        interval["getUsers"] = 30
        interval["getVideoConfiguration"] = 30
        interval["getLogicalDisk"] = 30
        interval["getMappedLogicalDisk"] = 30
        interval["getPhysicalMemory"] = 30
        interval["getPointingDevice"] = 60
        interval["getKeyboard"] = 60
        interval["getBaseBoard"] = 60
        interval["getDesktopMonitor"] = 60
        interval["getPrinters"] = 30
        interval["getNetworkLoginProfile"] = 30
        interval["getNetworkAdapters"] = 30
        interval["getPnPEntitys"] = 60
        interval["getSoundDevices"] = 60
        interval["getSCSIController"] = 120
        interval["getProducts"] = 60
        interval["getProcessor"] = 60
        interval["getFirewall"] = 60
        interval["getAgent"] = 180
        interval["getBattery"] = 30
        interval["getFilesystem"] = 30
        interval["getSharedDrives"] = 30
        interval["getEventLogs"] = 60
        interval["getWindowsUpdate"] = 1440
        self.AgentSettings['interval'] = interval
    
    # Set Agent Settings, 315/Commands/setAgentSettings, {"interval": {"getFilesystem": 30, "getBattery": 30}}
    def setAgentSettings(self, wmi, force=False, payload=""):
        print("Got Agent Settings")
        try:
            self.AgentSettings = json.loads(payload)        
        except Exception as e:
            self.log("setAgentSettings", e)

    # Show Alert
    def setAlert(self, wmi, force=False, payload=""):
        try:
            payload = json.loads(payload)
            response = ""
            if(payload["type"] == "alert"): response = pyautogui.alert(payload["message"], payload["title"], 'Okay')
            if(payload["type"] == "confirm"): response = pyautogui.confirm(payload["message"], payload["title"], ['Yes', 'No'])
            if(payload["type"] == "prompt"): response = pyautogui.prompt(payload["message"], payload["title"], '')
            if(payload["type"] == "password"): response = pyautogui.password(payload["message"], payload["title"], '', mask='*')
            Alert = {}
            Alert["Response"] = response
            self.mqtt.publish(str(self.ID) + "/Data/Alert", json.dumps(Alert), qos=1)
            print("Sending Alert Response: " + response)
        except Exception as e:
            self.log("setAlert", e)

    # Send Keys
    def setKeyboard(self, wmi, force=False, payload=""):
        try:
            time.sleep(0.5)
            pyautogui.FAILSAFE = True
            pyautogui.write(payload)
            print("Sending Keyboard Keys")
        except Exception as e:
            self.log("setKeyboard", e)

    # Heartbeat
    def Heartbeat(self, wmi, force=False, payload=""):
        return ""

    # Get Windows Update
    def getWindowsUpdates(self, wmi, force=False, payload=""):
        try:
            data = {}
            count = -1
            objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
            colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_QuickFixEngineering")
            for s in colItems:
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
                data[count] = subWindowsUpdates
                return data
        except Exception as e:
            self.log("GetWindowsUpdate", e)

    # Get Agent Settings
    def getAgentSettings(self, wmi, force=False, payload=""):
        return self.AgentSettings

    # Get General
    def getGeneral(self, wmi, force=False, payload=""):
        try:
            data = {}
            subGeneral = {}

            # Get Public IP Info
            IPInfo = urllib.request.urlopen('http://ipinfo.io/json').read().decode('utf8')
            subGeneral["ExternalIP"] = json.loads(IPInfo)

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
                subGeneral["NumberOfLogicalProcessors"] = s.HypervisorPresent
                subGeneral["NumberOfProcessors"] = s.HypervisorPresent
                subGeneral["Workgroup"] = s.Workgroup
                subGeneral["UserName"] = s.UserName
            data[0] = subGeneral
            return data
        except Exception as e:
            self.log("General", e)

    # Get Services
    def getServices(self, wmi, force=False, payload=""):
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
                data[count] = subService
            return data
        except Exception as e:
            self.log("Services", e)

    # Get BIOS
    def getBIOS(self, wmi, force=False, payload=""):  
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
            self.log("BIOS", e)         

    # Get Startup Items
    def getStartup(self, wmi, force=False, payload=""):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_StartupCommand(["Caption", "Location", "Command"]):
                count = count +1
                subStartup = {}
                subStartup["Location"] = s.Location
                subStartup["Command"] = s.Command
                subStartup["Caption"] = s.Caption     
                data[count] = subStartup
            return data
        except Exception as e:
            self.log("Startup", e)      

    # Get Optional Features
    def getOptionalFeatures(self, wmi, force=False, payload=""):
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
                data[count] = subOptionalFeatures
            return data
        except Exception as e:
            self.log("OptionalFeatures", e)

    # Get Processes
    def getProcesses(self, wmi, force=False, payload=""):
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
                data[count] = subProcesses
            return data
        except Exception as e:
            self.log("Processes", e)

    # Get User Accounts
    def getUsers(self, wmi, force=False, payload=""):
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
                subUserAccounts["FullName"] = s.Name
                subUserAccounts["LocalAccount"] = s.Name
                subUserAccounts["PasswordChangeable"] = s.Name
                subUserAccounts["PasswordExpires"] = s.PasswordExpires
                subUserAccounts["PasswordRequired"] = s.PasswordRequired
                subUserAccounts["Caption"] = s.Caption
                subUserAccounts["Name"] = s.Name 
                data[count] = subUserAccounts
            return data         
        except Exception as e:
            self.log("UserAccounts", e)

    # Get Video Configuration
    def getVideoConfiguration(self, wmi, force=False, payload=""):
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
                data[count] = subVideoConfiguration
            return data            
        except Exception as e:
            self.log("VideoConfiguration", e)

    # Get Logical Disk
    def getLogicalDisk(self, wmi, force=False, payload=""):
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
                data[count] = subLogicalDisk
            return data 
        except Exception as e:
            self.log("LogicalDisk", e)

    # Get Mapped Logical Disk
    def getMappedLogicalDisk(self, wmi, force=False, payload=""):
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
                data[count] = subMappedLogicalDisk
            return data 
        except Exception as e:
            self.log("MappedLogicalDisk", e)

    # Get Physical Memory
    def getPhysicalMemory(self, wmi, force=False, payload=""):
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
                data[count] = subPhysicalMemory
            return data
        except Exception as e:
            self.log("PhysicalMemory", e)

    # Get Pointing Device
    def getPointingDevice(self, wmi, force=False, payload=""):
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
                data[count] = subPointingDevice
            return data 
        except Exception as e:
            self.log("PointingDevice", e)

    # Get Keyboard
    def getKeyboard(self, wmi, force=False, payload=""):
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
                data[count] = subKeyboard
            return data
        except Exception as e:
            self.log("Keyboard", e)

    # Get BaseBoard
    def getBaseBoard(self, wmi, force=False, payload=""):
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
                data[count] = subBaseBoard
            return data
        except Exception as e:
            self.log("BaseBoard", e)

    # Get Desktop Monitor
    def getDesktopMonitor(self, wmi, force=False, payload=""):
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
                data[count] = subDesktopMonitor
            return data
        except Exception as e:
            self.log("DesktopMonitor", e)

    # Get Printers
    def getPrinters(self, wmi, force=False, payload=""):
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
                data[count] = subPrinter
            return data
        except Exception as e:
            self.log("Printers", e)
    
    # Get NetworkLoginProfile
    def getNetworkLoginProfile(self, wmi, force=False, payload=""):
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
                data[count] = subNetworkLoginProfile
            return data    
        except Exception as e:
            self.log("NetworkLoginProfile", e)

    # Get Network Adapters
    def getNetworkAdapters(self, wmi, force=False, payload=""):
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
                subNetworkAdapterIP = {}
                subNetworkAdapter["IPAddress"] = subNetworkAdapterIP
                data[count] = subNetworkAdapter
            # Only publish if changed
            return data
        except Exception as e:
            self.log("NetworkAdapters", e)

    # Get PnP Entitys
    def getPnPEntitys(self, wmi, force=False, payload=""):
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
                data[count] = subPnPEntity
            return data
        except Exception as e:
            self.log("PnPEntitys", e)

    # Get Sound Entitys
    def getSoundDevices(self, wmi, force=False, payload=""):
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
                data[count] = subSoundDevice
            return data
        except Exception as e:
            self.log("SoundDevices", e)

    # Get SCSI Controller
    def getSCSIController(self, wmi, force=False, payload=""):
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
                data[count] = subSCSIController
            return data
        except Exception as e:
            self.log("SCSIController", e)

    # Get Products
    def getProducts(self, wmi, force=False, payload=""):
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
                data[count] = subProduct
            return data
        except Exception as e:
            self.log("Products", e)

    # Get Processor
    def getProcessor(self, wmi, force=False, payload=""):
        try:
            wmi = wmi.WMI()
            count = -1
            data = {}
            for s in wmi.Win32_Processor(["Caption", "CpuStatus", "CurrentClockSpeed", "CurrentVoltage", "Description", "DeviceID", "Manufacturer", "MaxClockSpeed", "Name", "NumberOfCores", "NumberOfLogicalProcessors", "SerialNumber", "ThreadCount", "Version"]):
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
                data[count] = subProcessor
            return data
        except Exception as e:
            self.log("Processor", e)

    # Get Firewall
    def getFirewall(self, wmi, force=False, payload=""):
        try:
            data = {}
            subFirewall = {}
            subFirewall['currentProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show currentprofile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['publicProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show publicProfile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['privateProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show privateProfile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['domainProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show domainProfile state', shell=True).decode("utf-8") else 'OFF'
            data[0] = subFirewall
            return data  
        except Exception as e:
            self.log("Firewall", e)

    # Get Agent
    def getAgent(self, wmi, force=False, payload=""):
        try:
            data = {}
            subAgent = {}
            subAgent["Name"] = Service_Name
            subAgent["Version"] = Agent_Version
            subAgent["Path"] = os.path.dirname(os.path.abspath(__file__))
            data[0] = subAgent
            return data
        except Exception as e:
            self.log("Agent", e)

    # Get Battery
    def getBattery(self, wmi, force=False, payload=""):
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
                data[count] = subBattery
            return data
        except Exception as e:
            self.log("Battery", e)

    # Get Filesystem
    def getFilesystem(self, wmi, force=False, root="C://"):
        if(root == ""): root = "C://"
        print("Getting Filesystem: " + root)
        try:
            data = {}
            subFilesystem = []
            for item in os.listdir(root):
               subFilesystem.append(os.path.join(root, item).replace("\\","/"))
            data[0] = subFilesystem
            return data
        except Exception as e:
            self.log("Filesystem", e)

    # Get Screenshot
    def getScreenshot(self, wmi, force=False, payload=""):
        try:
            screenshot = pyautogui.screenshot()
            screenshot = screenshot.resize((800,800), PIL.Image.ANTIALIAS)

            with io.BytesIO() as output:          
                screenshot.save(output, format='JPEG')
                data = output.getvalue()
            return data
        except Exception as e:
            self.log("Screenshot", e)

    # Get Okla Speedtest
    def getOklaSpeedtest(self, wmi, force=False, payload=""):
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
            self.log("OklaSpeedtest", e)

    # Get Registry
    def getRegistry(self, wmi, force=False, payload=""):
        subRegistry = {}
        try:
            r = wmi.Registry()
            result, names = r.EnumKey(hDefKey=win32con.HKEY_LOCAL_MACHINE)
            for key in names:
                print(key)
        except Exception as e:
            self.log("Registry", e)

    # Get Shared Drives
    def getSharedDrives(self, wmi, force=False, payload=""):
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
                data[count] = subSharedDrives
            return data
        except Exception as e:
            self.log("SharedDrives", e)

    # Get Event Logs
    def getEventLogs(self, wmi, force=False, payload="System"):
        try:
            if(payload == ""): payload = "System"
            if(payload=="System" or payload=="Security" or payload=="Application" or payload=="Setup"):
                print("Getting " + payload + " Event Logs") 
                events = self.EventLogSupport(payload)
                count = 0
                data = {}
                for event in events:
                    count = count +1
                    data[count] = event
                    if(count == 100): break
                return data
            else:
                print("Event Log Type Not found in payload")
        except Exception as e:
            self.log("EventLogs", e)
        
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
            self.log("EventLogSupport", e)
                    
    # Run Code in CMD, Add Cache
    def CMD(self, command):
        try:
            returnData = subprocess.check_output(command.decode("utf-8"), shell=True)
            self.mqtt.publish(str(self.ID) + "/Data/CMD", returnData, qos=1)
        except Exception as e:
            self.log("CMD", e)

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OpenRMMAgent)

