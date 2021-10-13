#!/usr/bin/env python3

# TODo:
# Group, WindowsActivation
#
# Agent Settings

import os
from os.path import exists
import wmi
import paho.mqtt.client as mqtt
import json
import time
import subprocess
import threading
import pythoncom
import pyautogui
import io, sys
import PIL
import win32serviceutil, win32event, win32service
import servicemanager
import pkg_resources
import urllib.request
 
################################# SETUP ##################################
MQTT_Server = "****"
MQTT_Username = "****"
MQTT_Password = "****"
MQTT_Port = 1883

Service_Name = "OpenRMMAgent"
Service_Display_Name = "The OpenRMM Agent"
Service_Description = "A free open-source remote monitoring & management tool."

Agent_Version = "1.0"

LOG_File = "C:\OpenRMM.log"

###########################################################################

required = {'paho-mqtt', 'pyautogui', 'pywin32', 'wmi', 'pillow'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if missing:
    python = sys.executable
    subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)

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
        self.command = {}

        try:
            print("Setting up MQTT")
            import paho.mqtt.client as mqtt
            self.mqtt = mqtt.Client(client_id=self.hostname, clean_session=True)
            self.mqtt.username_pw_set(MQTT_Username, MQTT_Password)
            self.mqtt.will_set(self.hostname + "/Status", "Offline", qos=1, retain=True)
            self.mqtt.connect(MQTT_Server, port=MQTT_Port)
            self.mqtt.subscribe(self.hostname + "/Commands/#", qos=1)
            self.mqtt.on_message = self.on_message
            self.mqtt.on_connect = self.on_connect
            self.mqtt.on_disconnect = self.on_disconnect
            self.mqtt.loop_start()
        except Exception as e:
            self.log("SetupMQTT", e)

        print("Setting up WMI")
        import wmi
        pythoncom.CoInitialize()
        self.wmimain = wmi.WMI()

        self.Services = {}
        self.BIOS = {}
        self.General = {} 
        self.Startup = {}
        self.OptionalFeatures = {}
        self.Processes = {}
        self.UserAccounts = {}
        self.VideoConfiguration = {}
        self.PhysicalMemory = {}
        self.MappedLogicalDisk = {}
        self.LogicalDisk = {}
        self.Keyboard = {}
        self.PointingDevice = {}
        self.BaseBoard = {}
        self.DesktopMonitor = {}
        self.Printer = {}
        self.NetworkLoginProfile = {}
        self.NetworkAdapters = {}
        self.PnPEntitys = {}
        self.SoundDevices = {}
        self.SCSIController = {}
        self.Products = {}
        self.Processor = {}
        self.Firewall = {}
        self.Agent = {}
        self.Battery = {}
        self.Filesystem = {}

        print("Finished Setup")
        print("Configuring Threads")

        # Creating Threads
        self.threadGeneral = threading.Thread(target=self.startThread, args=["getGeneral", 30])
        self.threadBIOS = threading.Thread(target=self.startThread, args=["getBIOS", 60])
        self.threadStartup = threading.Thread(target=self.startThread, args=["getStartup", 30])
        self.threadOptionalFeatures = threading.Thread(target=self.startThread, args=["getOptionalFeatures", 30])
        self.threadProcesses = threading.Thread(target=self.startThread, args=["getProcesses", 30])
        self.threadServices = threading.Thread(target=self.startThread, args=["getServices", 30])
        self.threadUserAccounts = threading.Thread(target=self.startThread, args=["getUserAccounts", 30])
        self.threadVideoConfiguration = threading.Thread(target=self.startThread, args=["getVideoConfiguration", 30])
        self.threadLogicalDisk = threading.Thread(target=self.startThread, args=["getLogicalDisk", 30])
        self.threadMappedLogicalDisk = threading.Thread(target=self.startThread, args=["getMappedLogicalDisk", 30])
        self.threadPhysicalMemory = threading.Thread(target=self.startThread, args=["getPhysicalMemory", 30])
        self.threadPointingDevice = threading.Thread(target=self.startThread, args=["getPointingDevice", 60])
        self.threadKeyboard = threading.Thread(target=self.startThread, args=["getKeyboard", 60])
        self.threadBaseBoard = threading.Thread(target=self.startThread, args=["getBaseBoard", 60])
        self.threadDesktopMonitor = threading.Thread(target=self.startThread, args=["getDesktopMonitor", 60])
        self.threadPrinter = threading.Thread(target=self.startThread, args=["getPrinters", 60])
        self.threadNetworkLoginProfile = threading.Thread(target=self.startThread, args=["getNetworkLoginProfile", 60])
        self.threadNetworkAdapters = threading.Thread(target=self.startThread, args=["getNetworkAdapters", 60])
        self.threadPnPEntity = threading.Thread(target=self.startThread, args=["getPnPEntitys", 60])
        self.threadSoundDevice = threading.Thread(target=self.startThread, args=["getSoundDevices", 60])
        self.threadSCSIController = threading.Thread(target=self.startThread, args=["getSCSIController", 120])
        self.threadProduct = threading.Thread(target=self.startThread, args=["getProducts", 60])
        self.threadProcessor = threading.Thread(target=self.startThread, args=["getProcessor", 120])
        self.threadFirewall = threading.Thread(target=self.startThread, args=["getFirewall", 120])
        self.threadAgent = threading.Thread(target=self.startThread, args=["getAgent", 180])
        self.threadBattery = threading.Thread(target=self.startThread, args=["getBattery", 30])
        self.threadFilesystem = threading.Thread(target=self.startThread, args=["getFilesystem", 30]) 
        
        print("Finished Configuring Threads")
        print("Starting Command Loop") 
        print("Wating for Commands") 

        try:
            if(exists("ID.txt")):
                f = open("ID.txt", "r")
                self.ID = f.read()
                self.start()
        except Exception as e:
            self.log("SaveID", e)

        print("Starting Main")
        self.main()

    def stop(self):
        self.isrunning = False

    def main(self):
        while self.isrunning:
            try:
                print("ID is: " + str(self.ID))
                # Process commands
                while(True):
                    if "topic" in self.command:
                        if (self.command["topic"] == self.ID + "/Commands/getGeneral"): self.getGeneral(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getBIOS"): self.getBIOS(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getStartup"): self.getStartup(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getOptionalFeatures"): self.getOptionalFeatures(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getProcesses"): self.getProcesses(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getServices"): self.getServices(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getVideoConfiguration"): self.getVideoConfiguration(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getDisks"): self.getLogicalDisk(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getMappedLogicalDisk"): self.getMappedLogicalDisk(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getMemory"): self.getPhysicalMemory(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getPointingDevice"): self.getPointingDevice(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getKeyboard"): self.getKeyboard(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getBaseBoard"): self.getBaseBoard(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getDesktopMonitor"): self.getDesktopMonitor(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getPrinter"): self.getPrinters(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getNetworkLoginProfile"): self.getNetworkLoginProfile(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getNetwork"): self.getNetworkAdapters(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getPnPEntitys"): self.getPnPEntitys(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getSoundDevices"): self.getSoundDevices(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getSCSIController"): self.getSCSIController(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getProducts"): self.getProducts(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getUsers"): self.getUserAccounts(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getProcessor"): self.getProcessor(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getFirewall"): self.getFirewall(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getAgent"): self.getFirewall(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/getFilesystem"): self.getFilesystem(self.wmimain, True)
                        
                        if (self.command["topic"] == self.ID + "/Commands/getScreenshot"): self.getScreenshot(self.wmimain, True)
                        if (self.command["topic"] == self.ID + "/Commands/showAlert"): self.showAlert(self.command["payload"])

                        self.command = {}
            except Exception as e:
                self.log("GetCommands", e)

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, rc):
        print("MQTT connected with result code "+str(rc))
        self.mqtt.publish(self.hostname + "/Setup", "true", qos=1, retain=False)

    def on_disconnect(self, xclient, userdata, rc):
        if rc != 0:
            print("MQTT Unexpected disconnection.")

    def on_message(self, client, userdata, message):
        print("Received message '" + str(message.payload) + "' on topic '" + message.topic + "' with QoS " + str(message.qos))
        if (str(message.topic) == str(self.ID) + "/Commands/CMD"): self.CMD(message.payload)
        if (str(message.topic) == self.hostname + "/Commands/ID"): 
            self.ID = str(message.payload, 'utf-8')
            print("This Computers ID is: " + str(self.ID))

            # Save ID to File
            f = open("ID.txt", "w")
            f.write(self.ID)
            f.close()
            self.start()

        self.command["topic"] = message.topic
        self.command["payload"] = message.payload


    def startThread(self, name, minutes):
        import wmi
        pythoncom.CoInitialize()
        wmi = wmi.WMI()
        loopCount = 0
        result = eval("self." + name + "(wmi, False)")
        while True:
            time.sleep(1)
            loopCount = loopCount + 1
            if (loopCount == (60 * minutes)): # Every x minutes
                loopCount = 0
                result = eval("self." + name + "(wmi, False)")

    # Get General
    def getGeneral(self, wmi, force=False):
        print("Getting General")
        try:
            GeneralNew = {}
            subGeneral = {}
            externalIP = urllib.request.urlopen('https://ident.me').read().decode('utf8')
            subGeneral["ExternalIP"] = externalIP

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
            GeneralNew[0] = subGeneral

            # Only publish if changed
            if (GeneralNew != self.General or force == True):
                self.General = GeneralNew
                self.mqtt.publish(str(self.ID) + "/Data/General", json.dumps(self.General), qos=1)
                print("General Changed, Sending Data")
        except Exception as e:
            self.log("General", e)

    # Get Services
    def getServices(self, wmi, force=False):
        print("Getting Services")
        try:
            count = -1
            ServicesNew = {}
            for s in wmi.Win32_Service(["Caption", "Description", "Status", "DisplayName", "State", "StartMode"]):
                count = count +1
                subService = {}
                subService["Description"] = s.Description
                subService["Status"] = s.Status
                subService["DisplayName"] = s.DisplayName 
                subService["State"] = s.State
                subService["StartMode"] = s.StartMode
                subService["Caption"] = s.Caption
                ServicesNew[count] = subService

            # Only publish if changed
            if (ServicesNew != self.Services or force == True):
                self.Services = ServicesNew
                self.mqtt.publish(str(self.ID) + "/Data/Services", json.dumps(self.Services), qos=1)
                print("Services Changed, Sending Data")
        except Exception as e:
            self.log("Services", e) 

    # Get BIOS
    def getBIOS(self, wmi, force=False):  
        print("Getting BIOS")
        BIOSNew = {}
        try:
            for s in wmi.Win32_BIOS(["Caption", "Description", "Manufacturer", "Name", "SerialNumber", "Version", "Status"]):
                subBIOS = {}
                subBIOS["Caption"] = s.Caption
                subBIOS["Description"] = s.Description
                subBIOS["Manufacturer"] = s.Manufacturer
                subBIOS["Name"] = s.Name
                subBIOS["SerialNumber"] = s.SerialNumber
                subBIOS["Version"] = s.Version
                subBIOS["Status"] = s.Status
                BIOSNew[0] = subBIOS
            # Only publish if changed
            if (BIOSNew != self.BIOS or force == True):
                self.BIOS = BIOSNew
                self.mqtt.publish(str(self.ID) + "/Data/BIOS", json.dumps(self.BIOS), qos=1)
                print("BIOS Changed, Sending Data")
        except Exception as e:
            self.log("BIOS", e)         

    # Get Startup Items
    def getStartup(self, wmi, force=False):
        print("Getting Startup Items")
        try:
            count = -1
            StartupNew = {}
            for s in wmi.Win32_StartupCommand(["Caption", "Location", "Command"]):
                count = count +1
                subStartup = {}
                subStartup["Location"] = s.Location
                subStartup["Command"] = s.Command
                subStartup["Caption"] = s.Caption     
                self.Startup[count] = subStartup
            # Only publish if changed
            if (StartupNew != self.Startup or force == True):
                self.Startup = StartupNew
                self.mqtt.publish(str(self.ID) + "/Data/StartupItems", json.dumps(self.Startup), qos=1)
                print("Startup Changed, Sending Data")
        except Exception as e:
            self.log("Startup", e)      

    # Get Optional Features
    def getOptionalFeatures(self, wmi, force=False):
        print("Getting OptionalFeatures")
        try:
            OptionalFeaturesNew = {}
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
                OptionalFeaturesNew[count] = subOptionalFeatures
            # Only publish if changed
            if (OptionalFeaturesNew != self.OptionalFeatures or force == True):
                self.OptionalFeatures = OptionalFeaturesNew
                self.mqtt.publish(str(self.ID) + "/Data/OptionalFeatures", json.dumps(self.OptionalFeatures), qos=1)
                print("OptionalFeatures Changed, Sending Data")
        except Exception as e:
            self.log("OptionalFeatures", e)

    # Get Processes
    def getProcesses(self, wmi, force=False):
        print("Getting Processes")
        try:
            count = -1
            ProcessesNew = {}
            for s in wmi.Win32_Process(["Caption", "Description", "ParentProcessId", "ProcessId", "Status", "Name"]):
                count = count +1
                subProcesses = {}
                subProcesses["Description"] = s.Description
                subProcesses["ParentProcessId"] = s.ParentProcessId
                subProcesses["PID"] = s.ProcessId
                subProcesses["Status"] = s.Status
                subProcesses["Name"] = s.Name
                subProcesses["Caption"] = s.Caption
                self.Processes[count] = subProcesses
            # Only publish if changed
            if (ProcessesNew != self.Processes or force == True):
                self.Processes = ProcessesNew
                self.mqtt.publish(str(self.ID) + "/Data/Processes", json.dumps(self.Processes), qos=1)
                print("Processes Changed, Sending Data")
        except Exception as e:
            self.log("Processes", e)

    # Get User Accounts
    def getUserAccounts(self, wmi, force=False):
        print("Getting User Accounts")
        try:
            count = -1
            UserAccountsNew = {}
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
                self.UserAccounts[count] = subUserAccounts
            # Only publish if changed
            if (UserAccountsNew != self.UserAccounts or force == True):
                self.UserAccounts = UserAccountsNew
                self.mqtt.publish(str(self.ID) + "/Data/UserAccounts", json.dumps(self.UserAccounts), qos=1)
                print("UserAccounts Changed, Sending Data")         
        except Exception as e:
            self.log("UserAccounts", e)

    # Get Video Configuration
    def getVideoConfiguration(self, wmi, force=False):
        print("Getting Video Configuration")
        try:
            count = -1
            VideoConfigurationNew = {}
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
                self.VideoConfiguration[count] = subVideoConfiguration
            # Only publish if changed
            if (VideoConfigurationNew != self.VideoConfiguration or force == True):
                self.VideoConfiguration = VideoConfigurationNew
                self.mqtt.publish(str(self.ID) + "/Data/VideoConfiguration", json.dumps(self.VideoConfiguration), qos=1)
                print("VideoConfiguration Changed, Sending Data")             
        except Exception as e:
            self.log("VideoConfiguration", e)

    # Get Logical Disk
    def getLogicalDisk(self, wmi, force=False):
        print("Getting Logical Disk")
        try:
            count = -1
            LogicalDiskNew = {}
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
                self.LogicalDisk[count] = subLogicalDisk
            # Only publish if changed
            if (LogicalDiskNew != self.LogicalDisk or force == True):
                self.LogicalDisk = LogicalDiskNew
                self.mqtt.publish(str(self.ID) + "/Data/LogicalDisk", json.dumps(self.LogicalDisk), qos=1)
                print("LogicalDisk Changed, Sending Data")   
        except Exception as e:
            self.log("LogicalDisk", e)

    # Get Mapped Logical Disk
    def getMappedLogicalDisk(self, wmi, force=False):
        print("Getting Mapped Logical Disk")
        try:
            count = -1
            MappedLogicalDiskNew = {}
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
                self.MappedLogicalDisk[count] = subMappedLogicalDisk
            # Only publish if changed
            if (MappedLogicalDiskNew != self.MappedLogicalDisk or force == True):
                self.MappedLogicalDisk = MappedLogicalDiskNew
                self.mqtt.publish(str(self.ID) + "/Data/MappedLogicalDisk", json.dumps(self.MappedLogicalDisk), qos=1)
                print("MappedLogicalDisk Changed, Sending Data") 
        except Exception as e:
            self.log("MappedLogicalDisk", e)

    # Get Physical Memory
    def getPhysicalMemory(self, wmi, force=False):
        print("Getting Physical Memory")
        try:
            count = -1
            PhysicalMemoryNew = {}
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
                self.PhysicalMemory[count] = subPhysicalMemory
            # Only publish if changed
            if (PhysicalMemoryNew != self.PhysicalMemory or force == True):
                self.PhysicalMemory = PhysicalMemoryNew
                self.mqtt.publish(str(self.ID) + "/Data/PhysicalMemory", json.dumps(self.PhysicalMemory), qos=1)
                print("PhysicalMemory Changed, Sending Data") 
        except Exception as e:
            self.log("PhysicalMemory", e)

    # Get Pointing Device
    def getPointingDevice(self, wmi, force=False):
        print("Getting Pointing Device")
        try:
            count = -1
            PointingDeviceNew = {}
            for s in wmi.Win32_PointingDevice(["Caption", "Description", "DeviceID", "Manufacturer", "Name", "Status"]):
                count = count +1
                subPointingDevice = {}
                subPointingDevice["Caption"] = s.Caption
                subPointingDevice["Description"] = s.Description
                subPointingDevice["DeviceID"] = s.DeviceID
                subPointingDevice["Manufacturer"] = s.Manufacturer
                subPointingDevice["Name"] = s.Name
                subPointingDevice["Status"] = s.Status
                self.PointingDevice[count] = subPointingDevice
            # Only publish if changed
            if (PointingDeviceNew != self.PointingDevice or force == True):
                self.PointingDevice = PointingDeviceNew
                self.mqtt.publish(str(self.ID) + "/Data/PointingDevice", json.dumps(self.PointingDevice), qos=1)
                print("PointingDevice Changed, Sending Data") 
        except Exception as e:
            self.log("PointingDevice", e)

    # Get Keyboard
    def getKeyboard(self, wmi, force=False):
        print("Getting Keyboard")
        try:
            count = -1
            KeyboardNew = {}
            for s in wmi.Win32_Keyboard(["Caption", "Description", "DeviceID", "Name", "Status"]):
                count = count +1
                subKeyboard = {}
                subKeyboard["Caption"] = s.Caption
                subKeyboard["Description"] = s.Description
                subKeyboard["DeviceID"] = s.DeviceID
                subKeyboard["Name"] = s.Name
                subKeyboard["Status"] = s.Status
                self.Keyboard[count] = subKeyboard
            # Only publish if changed
            if (KeyboardNew != self.Keyboard or force == True):
                self.Keyboard = KeyboardNew
                self.mqtt.publish(str(self.ID) + "/Data/Keyboard", json.dumps(self.Keyboard), qos=1)
                print("Keyboard Changed, Sending Data")
        except Exception as e:
            self.log("Keyboard", e)

    # Get BaseBoard
    def getBaseBoard(self, wmi, force=False):
        print("Getting BaseBoard")
        try:
            count = -1
            BaseBoardNew = {}
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
                self.BaseBoard[count] = subBaseBoard
            # Only publish if changed
            if (BaseBoardNew != self.BaseBoard or force == True):
                self.BaseBoard = BaseBoardNew
                self.mqtt.publish(str(self.ID) + "/Data/BaseBoard", json.dumps(self.BaseBoard), qos=1)
                print("BaseBoard Changed, Sending Data")
        except Exception as e:
            self.log("BaseBoard", e)

    # Get Desktop Monitor
    def getDesktopMonitor(self, wmi, force=False):
        print("Getting Desktop Monitor")
        try:
            count = -1
            DesktopMonitorNew = {}
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
                self.DesktopMonitor[count] = subDesktopMonitor
            # Only publish if changed
            if (DesktopMonitorNew != self.DesktopMonitor or force == True):
                self.DesktopMonitor = DesktopMonitorNew
                self.mqtt.publish(str(self.ID) + "/Data/DesktopMonitor", json.dumps(self.DesktopMonitor), qos=1)
                print("DesktopMonitor Changed, Sending Data")
        except Exception as e:
            self.log("DesktopMonitor", e)

    # Get Printers
    def getPrinters(self, wmi, force=False):
        print("Getting Printers")
        try:
            count = -1
            PrinterNew = {}
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
                self.Printer[count] = subPrinter
            # Only publish if changed
            if (PrinterNew != self.Printer or force == True):
                self.Printer = PrinterNew
                self.mqtt.publish(str(self.ID) + "/Data/Printers", json.dumps(self.Printer), qos=1)
                print("Printer Changed, Sending Data")
        except Exception as e:
            self.log("Printers", e)
    
    # Get NetworkLoginProfile
    def getNetworkLoginProfile(self, wmi, force=False):
        print("Getting Network Login Profile")
        try:
            count = -1
            NetworkLoginProfileNew = {}
            for s in wmi.Win32_NetworkLoginProfile(["Caption", "Description", "FullName", "HomeDirectory", "Name", "NumberOfLogons"]):
                count = count +1
                subNetworkLoginProfile = {}
                subNetworkLoginProfile["Caption"] = s.Caption
                subNetworkLoginProfile["Description"] = s.Description
                subNetworkLoginProfile["FullName"] = s.FullName
                subNetworkLoginProfile["HomeDirectory"] = s.HomeDirectory
                subNetworkLoginProfile["Name"] = s.Name
                subNetworkLoginProfile["NumberOfLogons"] = s.NumberOfLogons
                self.NetworkLoginProfile[count] = subNetworkLoginProfile
            # Only publish if changed
            if (NetworkLoginProfileNew != self.NetworkLoginProfile or force == True):
                self.NetworkLoginProfile = NetworkLoginProfileNew
                self.mqtt.publish(str(self.ID) + "/Data/NetworkLoginProfile", json.dumps(self.NetworkLoginProfile), qos=1)
                print("NetworkLoginProfile Changed, Sending Data")    
        except Exception as e:
            self.log("NetworkLoginProfile", e)

    # Get Network Adapters
    def getNetworkAdapters(self, wmi, force=False):
        print("Getting Network Adapters")
        try:
            count = -1
            NetworkAdaptersNew = {}
            for s in wmi.Win32_NetworkAdapterConfiguration(["Caption", "Description", "DHCPEnabled", "DHCPLeaseExpires", "DHCPLeaseObtained", "DHCPServer", "DNSDomain", "MACAddress", "Index", "IPAddress"]):
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
                ipCount = 0
                #for ip_address in s.IPAddress:
                    #ipCount = ipCount +1
                    #subNetworkAdapterIP[ipCount] = ip_address

                subNetworkAdapter["IPAddress"] = subNetworkAdapterIP
                self.NetworkAdapters[count] = subNetworkAdapter
            # Only publish if changed
            if (NetworkAdaptersNew != self.NetworkAdapters or force == True):
                self.NetworkAdapters = NetworkAdaptersNew
                self.mqtt.publish(str(self.ID) + "/Data/NetworkAdapters", json.dumps(self.NetworkAdapters), qos=1)
                print("NetworkAdapters Changed, Sending Data")
        except Exception as e:
            self.log("NetworkAdapters", e)

    # Get PnP Entitys
    def getPnPEntitys(self, wmi, force=False):
        print("Getting PnP Entitys")
        try:
            count = -1
            PnPEntitysNew = {}
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
                self.PnPEntitys[count] = subPnPEntity
            # Only publish if changed
            if (PnPEntitysNew != self.PnPEntitys or force == True):
                self.PnPEntitys = PnPEntitysNew
                self.mqtt.publish(str(self.ID) + "/Data/PnPEntitys", json.dumps(self.PnPEntitys), qos=1)
                print("PnPEntitys Changed, Sending Data")
        except Exception as e:
            self.log("PnPEntitys", e)

    # Get Sound Entitys
    def getSoundDevices(self, wmi, force=False):
        print("Getting Sound Devices")
        try:
            count = -1
            SoundDevicesNew = {}
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
                self.SoundDevices[count] = subSoundDevice
            # Only publish if changed
            if (SoundDevicesNew != self.SoundDevices or force == True):
                self.SoundDevices = SoundDevicesNew
                self.mqtt.publish(str(self.ID) + "/Data/SoundDevices", json.dumps(self.SoundDevices), qos=1)
                print("SoundDevices Changed, Sending Data")
        except Exception as e:
            self.log("SoundDevices", e)

    # Get SCSI Controller
    def getSCSIController(self, wmi, force=False):
        print("Getting SCSI Controller")
        try:
            count = -1
            SCSIControllerNew = {}
            for s in wmi.Win32_SCSIController(["Caption", "Description", "DeviceID", "Manufacturer", "Name", "DriverName"]):
                count = count +1
                subSCSIController = {}
                subSCSIController["Caption"] = s.Caption
                subSCSIController["Description"] = s.Description
                subSCSIController["DeviceID"] = s.DeviceID
                subSCSIController["Manufacturer"] = s.Manufacturer
                subSCSIController["Name"] = s.Name
                subSCSIController["DriverName"] = s.DriverName
                self.SCSIController[count] = subSCSIController
            # Only publish if changed
            if (SCSIControllerNew != self.SCSIController or force == True):
                self.SCSIController = SCSIControllerNew
                self.mqtt.publish(str(self.ID) + "/Data/SCSIController", json.dumps(self.SCSIController), qos=1)
                print("SCSIController Changed, Sending Data")
        except Exception as e:
            self.log("SCSIController", e)

    # Get Products
    def getProducts(self, wmi, force=False):
        print("Getting Products")
        try:
            count = -1
            ProductsNew = {}
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
                self.Products[count] = subProduct
            # Only publish if changed
            if (ProductsNew != self.Products or force == True):
                self.Products = ProductsNew
                self.mqtt.publish(str(self.ID) + "/Data/Products", json.dumps(self.Products), qos=1)
                print("Products Changed, Sending Data")
        except Exception as e:
            self.log("Products", e)

    # Get Processor
    def getProcessor(self, wmi, force=False):
        print("Getting Processor")
        try:
            count = -1
            ProcessorNew = {}
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
                self.Processor[count] = subProcessor
            # Only publish if changed
            if (ProcessorNew != self.Processor or force == True):
                self.Processor = ProcessorNew
                self.mqtt.publish(str(self.ID) + "/Data/Processor", json.dumps(self.Processor), qos=1)
                print("Processor Changed, Sending Data")
        except Exception as e:
            self.log("Processor", e)

    # Get Firewall
    def getFirewall(self, wmi, force=False):
        print("Getting Firewall")
        try:
            FirewallNew = {}
            subFirewall = {}
            subFirewall['currentProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show currentprofile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['publicProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show publicProfile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['privateProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show privateProfile state', shell=True).decode("utf-8") else 'OFF'
            subFirewall['domainProfile'] = 'ON' if "ON" not in subprocess.check_output('netsh advfirewall show domainProfile state', shell=True).decode("utf-8") else 'OFF'
            self.Firewall[0] = subFirewall
            # Only publish if changed
            if (FirewallNew != self.Firewall or force == True):
                self.Firewall = FirewallNew
                self.mqtt.publish(str(self.ID) + "/Data/Firewall", json.dumps(self.Firewall), qos=1)
                print("Firewall Changed, Sending Data")  
        except Exception as e:
            self.log("Firewall", e)

    # Get Agent
    def getAgent(self, wmi, force=False):
        print("Getting Agent")
        try:
            AgentNew = {}
            subAgent = {}
            subAgent["Name"] = Service_Name
            subAgent["Version"] = Agent_Version
            self.Agent[0] = subAgent
            # Only publish if changed
            if (AgentNew != self.Agent or force == True):
                self.Agent = AgentNew
                self.mqtt.publish(str(self.ID) + "/Data/Agent", json.dumps(self.Agent), qos=1)
                print("Agent Changed, Sending Data")
        except Exception as e:
            self.log("Agent", e)

    # Get Battery
    def getBattery(self, wmi, force=False):
        print("Getting Battery")
        try:
            count = -1
            BatteryNew = {}
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
                self.Battery[count] = subBattery
            # Only publish if changed
            if (BatteryNew != self.Battery or force == True):
                self.Battery = BatteryNew
                self.mqtt.publish(str(self.ID) + "/Data/Battery", json.dumps(self.Battery), qos=1)
                print("Battery Changed, Sending Data")
        except Exception as e:
            self.log("Battery", e)

    # Get Filesystem
    def getFilesystem(self, wmi, force=False):
        print("Getting Filesystem")
        try:
            root = "C:\\"
            FilesystemNew = {}
            subFilesystem = []
            for root, dirs, files in os.walk(root):
                for d in dirs:
                    subFilesystem.append(os.path.join(root, d))
                for f in files:
                    subFilesystem.append(os.path.join(root, f))
            self.Filesystem["C"] = subFilesystem
            # Only publish if changed
            if (FilesystemNew != self.Filesystem or force == True):
                self.Filesystem = FilesystemNew
                self.mqtt.publish(str(self.ID) + "/Data/Filesystem", json.dumps(self.Filesystem), qos=1)
                print("Filesystem Changed, Sending Data")
        except Exception as e:
            self.log("Filesystem", e)

    def getScreenshot(self, wmi, force=False):
        print("Getting Screenshot")
        try:
            screenshot = pyautogui.screenshot()
            screenshot = screenshot.resize((800,800), PIL.Image.ANTIALIAS)

            with io.BytesIO() as output:          
                screenshot.save(output, format='JPEG')
                hex_data = output.getvalue()
            self.mqtt.publish(str(self.ID) + "/Data/Screenshot", hex_data, qos=1)
        except Exception as e:
            self.log("Screenshot", e)

    # Show Alert
    def showAlert(self, text):
        pyautogui.alert(text)

    # Run Code in CMD
    def CMD(self, command):
        try:
            returnData = subprocess.check_output(command.decode("utf-8"), shell=True)
            self.mqtt.publish(str(self.ID) + "/Data/CMD", returnData, qos=1)
        except Exception as e:
            self.log("CMD", e)

    def start(self):
        self.mqtt.subscribe(self.ID + "/Commands/#", qos=1)
        self.mqtt.unsubscribe(self.hostname + "/Commands/#")
        self.mqtt.publish(self.hostname + "/Status", "Online", qos=1, retain=True)

        print("Starting Threads")
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

        print("Finished Starting Threads")

    def log(self, name, message):
        print("Error in: "+name)
        print(message)
        try:
            f = open(LOG_File, "a")
            f.write("Error in: " + str(name) + ": " + str(message) + "\n")
            f.close()
        except Exception as e:
            print("Error saving to log file")
            print(e)

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(OpenRMMAgent)
