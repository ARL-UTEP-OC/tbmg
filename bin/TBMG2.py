import sys
sys.path.insert(0, '../')
sys.path.insert(0, '../scapyProxy')
from Tkinter import *
from ttkthemes import themed_tk
from ScrolledText import ScrolledText
from tkFileDialog import askopenfilename
import tkMessageBox
from jinja2 import Template
from io import BytesIO
import ttk
from PIL import ImageTk
import time
import os
import subprocess
from scapy.all import *
import sys
import importlib
import binascii
import inspect
from fieldObject import fieldObj
from StringIO import StringIO
from collections import OrderedDict
from scapyCustomizerTBMG import scapyCustomizerTBMG
from scapy_bridge3 import *
from GuiUtils import VerticalScrolledFrame
from AFLScapy import FuzzPacket
from HookUtils import HookProfile
import tkFileDialog
import threading
import netifaces
import datetime

class Application(Frame):
    def __init__(self, master):
        """initialize the frame"""
        Frame.__init__(self,master)
        application = self
        top = self.winfo_toplevel()
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.grid(sticky='NESW')
        self.create_widgets()
        self.root=root

    def create_widgets(self):
        self.expand1 = Label(page1, text='')
        self.expand1.grid(row=0, column=1, sticky='NEWS', columnspan=50)
        expand_h.append(self.expand1)
        #self.expand2 = Label(page1, text='')
        #self.expand2.grid(row=0, column=0, sticky='NEWS', rowspan=50)
        #expand_v.append(self.expand2)
        
        self.protocol = Label(page1, text="Protocol Name:")
        self.protocol.grid(row=1, column=0,  sticky = W)
        self.proto = Entry(page1)
        self.proto.grid(row=1, column=1,  sticky = W)


        self.pcapFile = Label(page1, text="Pcap File Path:")
        self.pcapFile.grid(row=2, column=0, sticky=W)
        self.pcapText = StringVar()
        self.pcap = Entry(page1, textvariable = self.pcapText)
        self.pcap.grid(row=2, column=1, sticky=W)
        self.choosePcap = Button(page1, text="Choose File", command=self.getPcapName)
        self.choosePcap.grid(row=2, column=2, sticky=W)

        self.dissectorFile = Label(page1, text="Dissector Name: (Optional)")
        self.dissectorFile.grid(row=3, column=0, sticky=W)
        self.dissectorText = StringVar()
        self.dissector = Entry(page1, textvariable=self.dissectorText)
        self.dissector.grid(row=3, column=1, sticky=W)
        self.chooseDissect = Button(page1, text="Choose File", command=self.getDissName)
        self.chooseDissect.grid(row=3, column=2, sticky=W)

        self.keyword = Label(page1, text="Keyword:")
        self.keyword.grid(row=4, column=0, sticky=W)
        self.key = Entry(page1)
        self.key.grid(row=4, column=1, sticky=W)

        self.modelName = Label(page1, text="Model-Name:")
        self.modelName.grid(row=5, column=0, sticky=W)
        self.model = Entry(page1)
        self.model.grid(row=5, column=1, sticky=W)

        self.createButton = Button(page1, text = "Create", command = self.create)
        self.createButton.grid(row = 10, column = 0, sticky = W)
        
        self.protnames = [x for x in os.listdir("./models") if ("__init__.py" not in x)]
        self.existingName = Label(page1, text="Use Existing:")
        self.existingName.grid(row=11, column = 0, sticky = W)
        self.existingvar = StringVar(page1)
        self.existingvar.set("Select Model...")
        self.existing = OptionMenu(page1, self.existingvar, self.existingvar.get(), *sorted(self.protnames))
        self.existing.grid(row=11,column=1,sticky=W)
        self.existingButton = Button(page1, text = "Load", command = self.loadexisting)
        self.existingButton.grid(row=11,column=2,sticky=W)
        
        self.newName = Label(page4, text="Protocol-Name:")
        self.newName.grid(row = 1, column=0, sticky=W)
        self.newNameField = Entry(page4)
        self.newNameField.grid(columnspan = 10, row=1, column=1, sticky=W)
        self.newNameField.insert(0, "ex. Protox")
        #############################################################
        self.line = ttk.Separator(page4, orient= HORIZONTAL)
        self.line.grid(row =3, columnspan = 20, sticky='ew', pady = 5)
        ###########################################################
        self.pattern = Label(page4, text="Pattern:")
        self.pattern.grid(row = 4,  column=0, sticky=W)
        self.transport = None
        self.fieldlist = None
        self.descLabel = None
        self.box_value = None
        #self.fieldArray = []
        self.fieldsArray = []
        self.completeTuple = {}
        self.fieldvar = StringVar(page4)
        
        self.layer =['IP', 'TCP', 'UDP']
        self.layervar = StringVar(page4)
        self.layervar.set("Layer")
        self.layerlist = OptionMenu(page4, self.layervar, self.layervar.get(), *self.layer, command = self.createFields)
        self.layerlist.grid(row=5,column=0,sticky=W)
        
        #############################################################
        self.line2 = ttk.Separator(page4, orient= HORIZONTAL)
        self.line2.grid(row =7, columnspan = 20, sticky='ew', pady = 5)
        #############################################################

        self.page5 = page5
        self.macs = [] #used for arp traffic
        self.interfaces = [] #used for scapy output
        for i in netifaces.interfaces():
            mac = netifaces.ifaddresses(i)[netifaces.AF_LINK][0]['addr']
            self.macs.append(mac)
            try:
                ip = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr']
            except:
                pass
            self.interfaces.append([str(i),ip,mac])
        self.output_interface = None
        self.iptables_interface = None
        print 'MY MACS:', self.macs
        self.scapybridgeS = ScapyBridge(self, True)
        self.scapybridgeR = ScapyBridge(self, False)
        
        def toggleProxyBoth():
            if not self.scapybridgeR.status:
                print 'saving iptables'
                os.system('iptables-save > ' + self.iptables_save)
            self.scapybridgeR.proxyToggle()
            self.scapybridgeS.proxyToggle()
            if self.scapybridgeS.intercepting and not self.scapybridgeS.status:
                self.extraInterceptedGUI(False)
                self.extraInterceptedGUI(True)
            if not self.scapybridgeR.status:
                print 'proxy is turned OFF'
                self.restoreIPTables()
            else:
                print 'proxy is turned ON'
            self.startproxy.config(bg=self.red)
            if self.scapybridgeR.status:
                self.startproxy.config(bg=self.green)
        
        def toggleInterceptBoth():
            self.scapybridgeR.interceptToggle()
            self.scapybridgeS.interceptToggle()
            self.extraInterceptedGUI(self.scapybridgeS.intercepting)
            time.sleep(.1)
            root_widgit.update_idletasks()
            root_widgit.configure(height=root_tab.winfo_reqheight())
            root_widgit.configure(width=root_tab.winfo_reqwidth())
            self.intercept.config(bg=self.red)
            if self.scapybridgeS.intercepting:
                self.intercept.config(bg=self.green)
        
        def file_save():
            #https://stackoverflow.com/questions/19476232/save-file-dialog-in-tkinter
            f = tkFileDialog.asksaveasfile(mode='w', defaultextension=".pcap")
            if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
                return
            self.scapybridgeR.pcapfile = f.name
            self.scapybridgeS.pcapfile = f.name
            print 'using',f.name
            f.close()
        
        def setFilter(args=None):
            self.scapybridgeS.filter = self.proxyfilter.get()
            self.scapybridgeR.filter = self.scapybridgeS
            print 'using filter:', self.scapybridgeS.filter
            self.defaultproxyfiltertext.config(bg=self.grey)
            if self.scapybridgeS.filter:
                self.defaultproxyfiltertext.config(bg=self.green)

        def sendFuzzer():
            print 'going to fuzz:'
            tab_text = self.traffic_tab.tab(self.traffic_tab.select(), "text")
            print 'traffic tab handle', tab_text
            if tab_text == 'Incoming':
                self.fuzz_packet = FuzzPacket(self.scapybridgeR.current_pack, tbmg_=self)
            elif tab_text == 'PCAP':
                self.fuzz_packet = FuzzPacket(self.scapybridgeS.current_packPCAP, tbmg_=self)
            else:
                self.fuzz_packet = FuzzPacket(self.scapybridgeS.current_pack, tbmg_=self)
            self.fuzz_packet.populateFuzzerGUI()
            nb2.tab(1, state='normal')
        
        def trafficTabHandle(args=None):
            tab_text = self.traffic_tab.tab(self.traffic_tab.select(),"text")
            print 'traffic tab handle', tab_text
            
            
        self.red = '#e85151'
        self.green = '#76ef51'
        self.yellow = '#f4e542'
        
        self.expand3 = Label(page5, text='')
        self.expand3.grid(row=0, column=0, sticky='NEWS', columnspan=50)
        expand_h.append(self.expand3)
        self.expand4 = Label(page5, text='')
        self.expand4.grid(row=0, column=0, sticky='NES', rowspan=50,columnspan=50)
        expand_v.append(self.expand4)
        
        self.startproxy = Button(page5, text='Proxy Toggle', command=toggleProxyBoth, bg=self.red)
        self.startproxy.grid(row=0, column=0+1, sticky='NEWS')
        
        self.intercept = Button(page5, text='Intercept Toggle', command=toggleInterceptBoth, bg=self.red)
        self.intercept.grid(row=0, column=1+1, sticky='NEWS')
        
        self.savepcap = Button(page5, text='Save Traffic\nto PCAP', command=file_save)
        self.savepcap.grid(row=0, column=2+1, sticky='NEWS')

        self.defaultproxyfiltertext = Button(page5, text="Filter:", command=setFilter)
        self.defaultproxyfiltertext.grid(row=1, column=0+1, sticky='NEWS')
        self.proxyfilter = Entry(page5)
        self.proxyfilter.bind("<Return>", setFilter)
        self.proxyfilter.grid(row=1, column=1+1, columnspan=3, sticky='NEWS')
        
        #traffic view
        self.traffic_tab = AutoresizedNotebookChild(page5)
        self.traffic_tab.bind('<Button-3>',trafficTabHandle)
        self.traffic_tab.grid(row=2, column=0+1, columnspan=50, rowspan=49, sticky='NEWS')

        self.grey = self.defaultproxyfiltertext.cget('background')
        
        #INCOMING
        self.incoming_frame = Frame(self.traffic_tab)
        self.traffic_tab.add(self.incoming_frame, text='Incoming')
        self.view_tab_in = AutoresizedNotebookChild(self.incoming_frame)
        self.view_tab_in.grid(row=0, column=0+1, columnspan=50, rowspan=49, sticky='NEWS')
        
        self.raw_tab_in = Frame(self.view_tab_in)
        self.view_tab_in.add(self.raw_tab_in, text='Raw',sticky='NESW')
        self.rawtextR = ScrolledText(self.raw_tab_in, height=30, width=90)
        self.rawtextR.grid(row=0, column=0+1, columnspan=5, sticky='NEWS')
        self.rawtextR.insert(END, 'RAWVIEW\n---\n')
        self.rawviewR = Button(self.raw_tab_in, text='Accept', command=self.scapybridgeR.sendRawUpdate)
        self.rawviewR.grid(row=1, column=0+1, sticky='SEW')
        self.dropR = Button(self.raw_tab_in, text='Drop', command=self.scapybridgeR.sendDrop)
        self.dropR.grid(row=1, column=1+1, sticky='SEW')
        self.sendoutfuzz = Button(self.raw_tab_in, text='Send to Fuzzer', command=sendFuzzer)
        self.sendoutfuzz.grid(row=1, column=2+1, sticky='SEW')

        self.disect_tab_in = Frame(self.view_tab_in)
        self.view_tab_in.add(self.disect_tab_in, text='Disect', sticky='NESW')
        self.disecttextR = ScrolledText(self.disect_tab_in, height=30, width=90)  # no intercept
        self.disecttextR.grid(row=0, column=0+1, columnspan=5, sticky='NEWS')
        self.disecttextR.insert(END, 'DISECT\n---\n')
        self.disectviewR = Button(self.disect_tab_in, text='Accept', command=self.scapybridgeR.sendDisectUpdate)
        self.disectviewR.grid(row=1, column=0+1, sticky='SEW')
        self.dropS = Button(self.disect_tab_in, text='Drop', command=self.scapybridgeR.sendDrop)
        self.dropS.grid(row=1, column=1+1, sticky='SEW')
        self.sendoutfuzz = Button(self.disect_tab_in, text='Send to Fuzzer', command=sendFuzzer)
        self.sendoutfuzz.grid(row=1, column=2+1, sticky='SEW')
        self.disectlistR = None
        self.disectLableR = None
        
        #OUTGOING
        self.outgoing_frame = Frame(self.traffic_tab)
        self.traffic_tab.add(self.outgoing_frame, text='Outgoing/Forwarded', sticky='NESW')
        self.view_tab_out = AutoresizedNotebookChild(self.outgoing_frame)
        self.view_tab_out.grid(row=0, column=0+1, sticky='EW')
        
        self.raw_tab_out = Frame(self.view_tab_out)
        self.view_tab_out.add(self.raw_tab_out, text='Raw', sticky='NESW')
        self.rawtextS = ScrolledText(self.raw_tab_out, height=30, width=90)
        self.rawtextS.grid(row=0, column=0+1, columnspan=5, sticky='NEWS')
        self.rawtextS.insert(END, 'RAWVIEW\n---\n')
        self.rawviewS = Button(self.raw_tab_out, text='Accept', command=self.scapybridgeS.sendRawUpdate)
        self.rawviewS.grid(row=1, column=0+1, sticky='SEW')
        self.dropS = Button(self.raw_tab_out, text='Drop', command=self.scapybridgeS.sendDrop)
        self.dropS.grid(row=1, column=1+1, sticky='SEW')
        self.sendoutfuzz = Button(self.raw_tab_out, text='Send to Fuzzer', command=sendFuzzer)
        self.sendoutfuzz.grid(row=1, column=2+1, sticky='SEW')

        self.disect_tab_out = Frame(self.view_tab_out)
        self.view_tab_out.add(self.disect_tab_out, text='Disect', sticky='NESW')
        self.disecttextS = ScrolledText(self.disect_tab_out, height=30, width=90)
        self.disecttextS.grid(row=0, column=0+1, columnspan=5, sticky='NEWS')
        self.disecttextS.insert(END, 'DISECT\n---\n')
        self.disectviewS = Button(self.disect_tab_out, text='Accept', command=self.scapybridgeS.sendDisectUpdate)
        self.disectviewS.grid(row=1, column=0+1, sticky='SEW')
        self.dropS = Button(self.disect_tab_out, text='Drop', command=self.scapybridgeS.sendDrop)
        self.dropS.grid(row=1, column=1+1, sticky='SEW')
        self.sendoutfuzz = Button(self.disect_tab_out, text='Send to Fuzzer', command=sendFuzzer)
        self.sendoutfuzz.grid(row=1, column=2+1, sticky='SEW')
        self.disectlistS = None
        self.disectLableS = None
        
        #PCAPs
        def replacer(is_outgoing):
            if not self.scapybridgeS.intercepting:
                tkMessageBox.showinfo('TMBG - Not Intercepting', 'To replace a packet, make sure INTERCEPTING is on.')
                return
            if not self.scapybridgeS.current_packPCAP:
                tkMessageBox.showinfo('TMBG - Not Intercepting', 'To replace a packet, make sure a packet from a PCAP is selected.')
                return
            if is_outgoing:
                self.traffic_tab.select(1)
                self.scapybridgeS._packet_disect_intercept(self.scapybridgeS.current_packPCAP, True)
            else:
                self.traffic_tab.select(0)
                self.scapybridgeR._packet_disect_intercept(self.scapybridgeS.current_packPCAP, True)
            
        self.pcap_frame = Frame(self.traffic_tab)
        self.traffic_tab.add(self.pcap_frame, text='PCAP', sticky='NESW')
        self.view_tab_pcap = AutoresizedNotebookChild(self.pcap_frame)
        self.view_tab_pcap.grid(row=0, column=0+1, sticky='NEWS')

        self.pcap_tab = Frame(self.view_tab_pcap)
        self.view_tab_pcap.add(self.pcap_tab, text='Packets', sticky='NESW')
        self.loadPacksFromPcap = Button(self.pcap_tab, text='Load from PCAP', command=self.scapybridgeS.loadPCAP,width=85)
        self.loadPacksFromPcap.grid(row=0, column=0+1, sticky='NEWS')
        self.pack_view = VerticalScrolledFrame(self.pcap_tab, height=30, width=100)
        self.pack_view_fixwidth = Label(self.pack_view.interior, text='')
        self.pack_view_fixwidth.configure(width=75)
        self.pack_view_fixwidth.grid(row=0, column=0)
        self.pack_view.grid(row=1,column=0+1, sticky='NEWS')
        
        self.raw_tab_pcap = Frame(self.view_tab_pcap)
        self.view_tab_pcap.add(self.raw_tab_pcap, text='Raw', sticky='NESW')
        self.rawtextP = ScrolledText(self.raw_tab_pcap, height=30, width=60)
        self.rawtextP.grid(row=0, column=0+1, columnspan=5, sticky='NEWS')
        self.rawtextP.insert(END, 'RAWVIEW\n---\n')
        self.rawviewP = Button(self.raw_tab_pcap, text='Send', command=self.scapybridgeS.sendRawUpdate)
        self.rawviewP.grid(row=1, column=0+1, sticky='SEW')
        self.rawdropP = Button(self.raw_tab_pcap, text='Drop', command=self.scapybridgeS.sendDrop)
        self.rawdropP.grid(row=1, column=1+1, sticky='SEW')
        self.rawviewPS = Button(self.raw_tab_pcap, text='Replace Outgoing\n Packet', command=lambda is_outgoing=True:replacer(is_outgoing))
        self.rawviewPS.grid(row=1, column=2+1, sticky='SEW')
        self.rawviewPR = Button(self.raw_tab_pcap, text='Replace Incoming\n Packet', command=lambda is_outgoing=False:replacer(is_outgoing))
        self.rawviewPR.grid(row=1, column=3+1, sticky='SEW')
        self.rawsendoutfuzz = Button(self.raw_tab_pcap, text='Send to Fuzzer', command=sendFuzzer)
        self.rawsendoutfuzz.grid(row=1, column=4+1, sticky='SEW')

        self.disect_tab_pcap = Frame(self.view_tab_pcap)
        self.view_tab_pcap.add(self.disect_tab_pcap, text='Disect', sticky='NESW')
        self.disectlistP = VerticalScrolledFrame(self.disect_tab_pcap, height=30, width=50)
        self.disectlistP.grid(row=0, column=0, columnspan=6)
        self.disectLableP = Label(self.disectlistP.interior, text='DISECT VIEW\n----\n')
        self.disectLableP.grid(row=0, column=0)
        self.disectviewP = Button(self.disect_tab_pcap, text='Send_Disect', command=self.scapybridgeS.sendDisectUpdate)
        self.disectviewP.grid(row=1, column=0+1, sticky='SEW')
        self.disectdropP = Button(self.disect_tab_pcap, text='Drop', command=self.scapybridgeS.sendDrop)
        self.disectdropP.grid(row=1, column=1+1, sticky='SEW')
        self.disectviewPS = Button(self.disect_tab_pcap, text='Replace Outgoing\n Packet', command=lambda is_outgoing=True:replacer(is_outgoing))
        self.disectviewPS.grid(row=1, column=2+1, sticky='SEW')
        self.disectviewPR = Button(self.disect_tab_pcap, text='Replace Incoming\n Packet', command=lambda is_outgoing=False:replacer(is_outgoing))
        self.disectviewPR.grid(row=1, column=3+1, sticky='SEW')
        self.disectsendoutfuzz = Button(self.disect_tab_pcap, text='Send to Fuzzer', command=sendFuzzer)
        self.disectsendoutfuzz.grid(row=1, column=4+1, sticky='SEW')

        #############################################################
        #############################################################
        self.page6 = page6
        self.timers = []
        self.updateTimers()
        #############################################################
        #############################################################
        self.page7 = page7
        self.active_hook_profile = HookProfile(tbmg=self)
        
        
        def askForProfile():
            name = tkFileDialog.askopenfilename(initialdir="/root/tbmg/bin/Profiles", filetypes=[("Profile XML", "*.xml")])
            if not name:
                return
            self.active_hook_profile.loadFromXML(name)
            
        def askSaveProfile():
            name = tkFileDialog.asksaveasfile(mode='w', defaultextension=".xml", initialdir="/root/tbmg/bin/Profiles")
            if not name:
                return
            self.active_hook_profile.saveTo(name)
         
        self.addhook = Button(page7, text="Add Hook...", command=self.active_hook_profile.chooseHook)
        self.addhook.grid(row=0, column=0, sticky='NEWS')
        self.loadprofile = Button(page7, text="Load Profile...", command=askForProfile)
        self.loadprofile.grid(row=0, column=1, sticky='NEWS')
        self.scrollhooks = VerticalScrolledFrame(page7)
        self.scrollhooks.grid(row=1, column=0, columnspan=2, sticky='NEWS')
        self.scrollhooks_width = Label(self.scrollhooks.interior, text='', width=80)
        self.scrollhooks_width.grid(row=0, column=0, sticky="NEW")
        self.saveprofile = Button(page7, text='Save Profile...', command=askSaveProfile)
        self.saveprofile.grid(row=2, column=0, columnspan=2, sticky='NEWS')
        self.updateHookGUI()
        #############################################################
        #############################################################
        self.page8 = page8
        self.output_interface = None
        self.iptables_interface = None
            
        def popUpInterfaces_ScapyOutput():
            def setOutputInterface(name):
                self.output_interface = name
                print 'OUT INTERFACE = ', name
                popup.destroy()
            popup = Toplevel()
            popup.title = 'Select Output Interface'
            scroll = VerticalScrolledFrame(popup)
            scroll.pack()
            for device in self.interfaces:
                print 'devices:',device
                b = Button(scroll, text=(device[0]+"; "+device[1]+"; "+device[2]), command=lambda name=device[0]: setOutputInterface(name))
                b.pack(fill=X)
            b = Button(scroll, text='Default', command=lambda: setOutputInterface(None))
            b.pack(fill=X)

        def popUpInterfaces_IptablesInterface():
            def setIptablesInterface(name):
                self.iptables_interface = name
                print 'IPTABLES INTERFACE = ', name
                self.scapybridgeR.defineIptableRules()
                self.scapybridgeS.defineIptableRules()
                popup.destroy()
            popup = Toplevel()
            popup.title = 'Select Output Interface'
            scroll = VerticalScrolledFrame(popup)
            scroll.pack()
            for device in self.interfaces:
                print 'devices:',device
                b = Button(scroll, text=(device[0]+"; "+device[1]+"; "+device[2]), command=lambda name=device[0]: setIptablesInterface(name))
                b.pack(fill=X)
            b = Button(scroll, text='Default', command=lambda: setIptablesInterface(None))
            b.pack(fill=X)
        
        self.select_out_interface = Button(page8, text='Select Scapy Output\nInterface', command=popUpInterfaces_ScapyOutput)
        self.select_out_interface.grid(row=0, column=0, sticky='NEWS')

        self.select_iptables_interface = Button(page8, text='Select Iptables\nInterface', command=popUpInterfaces_IptablesInterface)
        self.select_iptables_interface.grid(row=1, column=0, sticky='NEWS')
        #############################################################
        #############################################################
        self.iptables_save = '/root/tbmg/bin/iptables_save.txt'
        self.extraInterceptedGUI_lock = Lock()

    def updateHookGUI(self):
        def toggleActive(index):
            self.active_hook_profile.toggleActivateHook(index)
        
        def removeHook(index):
            self.active_hook_profile.delHook(index)
        
        def displayDescription(index):
            popup = Toplevel()
            popup.title = "About"
            text = self.active_hook_profile.hook_manager[index][4]
            new_text= ''
            for i in range(0,len(text),50):
                new_text= new_text+text[i:i+50]+'\n'
            if len(text)==0 or text==None or text=='None':
                new_text="This hook has no description"
            label = Label(popup, text=new_text, width=50)
            label.grid(row=0,column=0,sticky='NEWS',columnspan=3)
            done = Button(popup,text='OK',command=popup.destroy)
            done.grid(row=1,column=1,sticky='NEWS')
        
        
        if hasattr(self, 'active_hook_profile'):
            for w in self.scrollhooks.interior.winfo_children():
                if w == self.scrollhooks_width:
                    continue
                w.destroy()
            i=0
            for hook in self.active_hook_profile.hook_manager:
                frame = Frame(self.scrollhooks.interior, width=70)
                frame.grid(row=i, column=0)
                label = Label(frame, text=hook[0].__name__, width=40)
                label.grid(row=0, column=0, sticky='NEWS')
                activate = Button(frame, width=10, command= lambda index=i: toggleActive(index))
                activate.grid(row=0, column=1, sticky='NEWS')
                if hook[5]:
                    activate.config(bg=self.green)
                    activate.config(text='Y')
                else:
                    activate.config(bg=self.red)
                    activate.config(text='N')
                delete = Button(frame, text='Remove', width=10, command= lambda index=i: removeHook(index))
                delete.grid(row=0, column=2, sticky='NEWS')
                about = Button(frame, text='?', width=10, command= lambda index=i: displayDescription(index))
                about.grid(row=0, column=3, sticky='NEWS')
                i += 1

    def extraInterceptedGUI(self, is_intercepting):
        self.extraInterceptedGUI_lock.acquire()
        if is_intercepting:
            # intercpetd queue
            self.netqueueframeS = VerticalScrolledFrame(self.disect_tab_out, height=100, width=40)
            self.netqueueframeS.grid(row=0, column=3, columnspan=2)
            self.netqueueLableS = Label(self.netqueueframeS.interior, text='NET QUEUE\n----\n', width='95')
            self.netqueueLableS.pack()
            self.interceptsizelabelS = Label(self.disect_tab_out, width=5)
            self.interceptsizelabelS.grid(row=0, column=6)
        
            self.netqueueframeR = VerticalScrolledFrame(self.disect_tab_in, height=100, width=40)
            self.netqueueframeR.grid(row=0, column=3, columnspan=2)
            self.netqueueLableR = Label(self.netqueueframeR.interior, text='NET QUEUE\n----\n', width='95')
            self.netqueueLableR.pack()
            self.interceptsizelabelR = Label(self.disect_tab_in, width=5)
            self.interceptsizelabelR.grid(row=0, column=6)
    
        else:
            try:
                #self.netqueueLableS.destroy()
                self.netqueueframeS.destroy()
                #self.netqueueLableR.destroy()
                self.netqueueframeR.destroy()
                self.loadPacksFromPcap.destroy()
                self.pack_view.destroy()
            except:
                pass
        print 'finished extraInterceptedGUI', is_intercepting
        self.extraInterceptedGUI_lock.release()
        
    def restoreIPTables(self):
        try:
            if os.path.isfile(self.iptables_save):
                os.system('iptables-restore ' + self.iptables_save)
                #os.remove(self.iptables_save)
                print 'restored iptables'
        except:
            print 'TROUBLE RESTORING IPTABLES************************'
        
    def updateTimers(self):
        now = datetime.datetime.now().strftime("%H:%M:%S.%f")
        now_time = datetime.datetime.strptime(now, '%H:%M:%S.%f')
        for timer in self.timers:
            old = timer.cget('text').split(';')[0]
            old_time = datetime.datetime.strptime(old, '%H:%M:%S.%f')
            secs = (now_time-old_time).seconds
            timer.config(text=(old + '; ' + str(secs)))
            if secs > 30:
                timer.config(bg=self.red)
            elif secs >= 15:
                timer.config(bg=self.yellow)
        root.after(3000, self.updateTimers)
    
#######################################################################################
#######################################################################################
#before my time vvvvv - the4960
#######################################################################################
#######################################################################################
    
    def grabTransport(self):  #grabbing the values entered by user for the dissector table
		if self.transport != None:
			self.ports.grid_remove()
			self.portsEntry.grid_remove()
		
		self.transport = self.connectChosen.get()
		self.ports = Label(page4, text = "Enter Port(s)")
		self.ports.grid(row = 3, column=0,sticky = W)
		self.portsEntry = Entry(page4)
		self.portsEntry.grid(row = 3, columnspan = 200, column = 1, sticky=W)
		self.portsEntry.insert(0, "ex: 80;8080")
		print(self.transport)
		
    def createFields(self, layer): #for the drop down in dissector screen
		if layer != "Layer":
			print self.box_value
			if self.box_value!=None:
				if self.descLabel !=None:
					self.descLabel.grid_forget()
				
			print layer
			fields = {}
			field_name= []
			
			if layer=='TCP':
				fieldlist = 'fields/tcpfields.txt'
			elif layer=='UDP':
				fieldlist = 'fields/udpfields.txt'
			else:
				fieldlist = 'fields/ipfields.txt'
			with open(fieldlist) as f:
					lines = f.readlines()
					for line in lines:
						splitline = line.split(';',2)
						name = splitline[0]
						descr = splitline[1]
						field_name.append(name)
						#fields.append(field)
						fields[name] = descr
			def getdesc(field_value):
				if self.descLabel != None:
					self.descLabel.destroy()
				selectedField = self.box_value.get()
				description=fields[selectedField]
				self.descLabel = Label(page4, text = description)
				self.descLabel.grid(row = 5, column=3,sticky = W)
				self.addLabel = Label(page4, text = "New Unique Message")
				self.addLabel.grid(row = 9, column=0,sticky = W)
				self.exampleLabel = Label(page4, text="ex. udp.port = 8890;8880")
				self.exampleLabel.grid(row = 6, column=1,  sticky=W)
				self.addButton = Button(page4, text = "+", command=self.messageTypeCreator)
				self.addButton.grid(row=9, column =1 , sticky = W)
				self.generateButton = Button(page4, text = "Generate", command=self.createDissector)
				self.generateButton.grid(row=10, column = 0, sticky = W)
				
			
			self.box_value = StringVar()
			fieldbox = ttk.Combobox(page4, textvariable=self.box_value, values=field_name)
			#cb3.current(0)  # set selection
			fieldbox.grid(row=5,column=1,sticky=W)
			
			fieldbox.bind("<<ComboboxSelected>>", getdesc)

    def create(self):
		proto = self.proto.get()
		if not proto:
			popupmsg("Error Message: Protocol name was not specified")
		jinjaXMLInputFilename = "templates/config.jnj2"
		jinjaXMLOutputFilename = "sampleConfigs/"+proto + ".xml"

		pcap = self.pcap.get()
		if not pcap:
			popupmsg("Error Message: Pcap File not specified")
		dissector = self.dissector.get()
		keyword = self.key.get()
		if not keyword:
			popupmsg("Error Message: Keyword was not specified")
		model = self.model.get()
		if not model:
			popupmsg("Error Message: model was not specified")
		with open(jinjaXMLInputFilename) as f:
			template = Template(f.read())
			xmlOutput = template.render(jinjaProtocolName=proto, jinjaDissectorName=dissector, jinjaPcapName=pcap, jinjaMessageID=keyword, jinjaModelName = model)
		with open(jinjaXMLOutputFilename, 'w') as o:
			o.write(xmlOutput)
		print(proto)
		print(pcap)
		print(dissector)
		print(keyword)
		print(model)
		time.sleep(5)
		runtbmg(proto, model)
		#self.popupmsg("Config File Created. Find in /sampleConfigs")
		

    def createDissector(self):#for Dissector Generator
		global fieldArray
		print "Under Construction"
		for line in fieldArray:
			print line.get()
		#print self.fieldArray
		#ports = []
		#proto_name = self.newNameField.get()
		#proto_pattern = self.portsEntry.get()
		#prts = self.portsEntry.get()
		#ports = prts.split(';', 1)
		#print ports
		#if self.transport == None:
			#self.transport = 'ethertype'
		#elif self.transport == 'TCP':
			#self.transport = 'tcp.port'
		#else:
			#self.transport = 'udp.port'
		
		#jinjaDissectorInput = "templates/dissector_template.jnj2"
		#jinjaDissectorOutput = "dissectors/"+proto_name+"_dissector.lua"
		#with open(jinjaDissectorInput) as f:
			#template = Template(f.read())
			#dissectorOut = template.render(jinjaProtocolName = proto_name, jinjaPorts = ports, jinjaTrans = (self.transport))
		#with open(jinjaDissectorOutput, 'w') as o:
			#o.write(dissectorOut)
		
    def messageTypeCreator(self):##for dissector generator
		popup = Tk()
		global fieldArray
		def closepopup():
			popup.withdraw()
		popup.wm_title("Message Type Creator")
		def addnewfield():
			global firstField
			fname=Entry(popup)
			fieldArray.append(fname)
			fname.grid(row = firstField, columnspan = 1, column=0, sticky="w")
			fstart=Entry(popup, width=7)
			fieldArray.append(fstart)
			fstart.grid(row = firstField,columnspan = 1,column=1, sticky="w")
			flen=Entry(popup, width=7)
			fieldArray.append(flen)
			flen.grid(row = firstField,columnspan = 1,column=2, sticky="w")
			ftype=Entry(popup)
			fieldArray.append(ftype)
			ftype.grid(row = firstField,columnspan = 1,column=3, sticky="w")
			fpattern=Entry(popup, width=10)
			fieldArray.append(fpattern)
			fpattern.grid(row = firstField,columnspan = 1,  column=4, sticky="w")
			firstField +=1
		#####Labels on top#######
		field_name_label = Label(popup, text="Field Name")
		field_name_label.grid(row = 0, column=0, sticky="w")
		start_label = Label(popup, text="Start")
		start_label.grid(row=0, column =1, sticky ="w")
		len_label = Label(popup, text="Len")
		len_label.grid(row=0, column =2, sticky ="w")
		type_label = Label(popup, text="Unique Type")
		type_label.grid(row=0, column =3, sticky ="w")
		pattern_label = Label(popup, text="Pattern")
		pattern_label.grid(row=0, column =4, sticky ="w")
		
		######Entry Boxes######
		fname=Entry(popup)
		fieldArray.append(fname)
		fname.grid(row=1, columnspan = 1, column=0, sticky="w")
		fstart=Entry(popup, width=7)
		fieldArray.append(fstart)
		fstart.grid(row=1, columnspan = 1,column=1, sticky="w")
		flen=Entry(popup, width=7)
		fieldArray.append(flen)
		flen.grid(row=1, columnspan = 1,column=2, sticky="w")
		ftype=Entry(popup)
		fieldArray.append(ftype)
		ftype.grid(row=1, columnspan = 1,column=3, sticky="w")
		fpattern=Entry(popup, width=10)
		fieldArray.append(fpattern)
		fpattern.grid(row=1, columnspan = 1,  column=4, sticky="w")
		
		
		######Creator Popup Buttons#######
		lastrow = 100
		addField = ttk.Button(popup, text="+", command = addnewfield)
		addField.grid(row = lastrow, column =0, pady=5)
		B1 = ttk.Button(popup, text="Create", command = self.createDissector)
		B1.grid(row = lastrow, column =1, pady=5)
		cancelButton = ttk.Button(popup, text="Done", command = closepopup)
		cancelButton.grid(row = lastrow, column =2, pady=5)
		popup.mainloop()
		
    def loadexisting(self):
        displayModels(self.existingvar.get())

    # def update_text(self):
        # global hidden
        # print hidden
    # #if the "Create TCP" box is checked

            # # Source IP address box appears
        # self.ipSource = Label(page2, text="Source IP:")
        # self.src = Entry(page2)


            # # Destination IP address box appears
        # self.ipdestination = Label(page2, text="Destination IP:")
        # self.dst = Entry(page2)

            # #Request optional port
        # self.prt = Label(page2, text="Port (Optional):")
        # self.port = Entry(page2)

        # if hidden == True:
            # self.ipSource.grid(row=0, column=0, sticky=W)
            # self.src.grid(row=0, column=1, sticky=W)

            # self.ipdestination.grid(row=1, column=0, sticky=W)
            # self.dst.grid(row=1, column=1, sticky=W)

            # self.prt.grid(row=2, column=0, sticky=W)
            # self.port.grid(row=2, column=1, sticky=W)
            # hidden = False
        # else:
            # self.ipSource.grid_forget()
            # self.src.grid_forget()

            # self.ipdestination.grid_forget()
            # self.dst.grid_forget()

            # self.prt.grid_forget()
            # self.port.grid_forget()
            # hidden = True
        # print hidden

    def getPcapName(self):
        pcapname = askopenfilename(initialdir="sampleConfigs/captures")
        self.pcapText.set(pcapname)

    def getDissName(self):
        dissectorName = askopenfilename(initialdir="dissectors/")
        self.dissectorText.set(dissectorName)
        
	

def runtbmg(proto, modelname):
	samConfig = "sampleConfigs/"+proto+".xml"
	print samConfig
	try:
		subprocess.check_call(["python", "modelGenerator.py", samConfig])
		
	except Exception as e:
		#print "########################Caught an exception##########################"
		
		popupmsg(str(e))
		exit
	displayModels(modelname)
	
def popupmsg(msg):
		popup = Tk()
		def closepopup():
			popup.destroy()
		popup.wm_title("Message")
		label = ttk.Label(popup, text = msg)
		label.pack(side="top", pady=10)
		B1 = ttk.Button(popup, text="Okay", command = closepopup)
		B1.pack()
		popup.mainloop()
		
def displayModels(modelname):
	#Clear the contents in page2
	
	for child in page2.winfo_children():
		child.destroy()
	model_resize = Label(page2, text="")
	model_resize.grid(row=0, column=0, sticky='NS', columnspan=10)
	selectLabel = Label(page2, text="Select Model:", font = "bold")
	selectLabel.grid(sticky = "W")
	models = []
	models = os.listdir(os.path.join("models",modelname,"scapy","model"))
	modelChosen = StringVar()
	connectChosen = StringVar()
	path1 = os.path.join("models",modelname,"__init__.py")
	path2 = os.path.join("models",modelname,"scapy","__init__.py")

#create required init.py files for importing if not existent
	open(path1, 'a')
	open(path2, 'a')
	#show the created protocols
	for model in models:
		if model != "__init__.py" and model != modelname+"Client.py" and model[-3:] == '.py':
			pickModel = Radiobutton(page2, text=model[:-3], padx = 20, variable = modelChosen, value = model)
			pickModel.grid(sticky = "W")
	createLabel = Label(page2, text="Create:", font = "bold")
	createLabel.grid(sticky = "W")
	tcp = Radiobutton(page2, text="TCP", padx = 20, value = "TCP", variable = connectChosen)
	tcp.grid(sticky = "W")
	udp = Radiobutton(page2, text="UDP", padx = 20, value = "UDP", variable = connectChosen)
	udp.grid(sticky = "W")
	raw = Radiobutton(page2, text="RAW", padx = 20, value = "RAW", variable = connectChosen)
	raw.grid(sticky = "W")
	
	viewButton = Button(page2, text = "View", command = lambda: showmodeldata(modelname, modelChosen.get(), connectChosen.get()))
	viewButton.grid()
	
	editButton = Button(page2, text = "Edit", command = lambda: modifymodeldata(modelname, modelChosen.get(), connectChosen.get()))
	editButton.grid()

	nb.select(page2)
	global show
	if show != None:
		show.delete(1.0, END)
	else:
		show = Text(page2)
        show.insert(0.0,'\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n')
	show.grid(sticky="W")
	
	#self.tcp = BooleanVar()
        #Checkbutton(page2, text= "Create TCP Connection", variable = self.tcp, command = self.update_text).grid(row =6, column = 0, sticky = W)
def buildscapyproto(name,modeltype,connecttype):
	global mod_model, mod_class
	
	modelpath = name + "/scapy/"
	model_strip = modeltype.strip(".py")

	mod_model = importlib.import_module("models."+name+".scapy.model."+model_strip)
	mod_class = getattr(mod_model,model_strip)
	protLayer = mod_class()
	if connecttype == "RAW":
		ipLayer = IP(dst="127.0.0.1")/protLayer
	elif connecttype == "TCP":
		xcpLayer = TCP()/protLayer
		ipLayer  = IP(dst="127.0.0.1")/xcpLayer
	else:
		xcpLayer = UDP()/protLayer
		ipLayer  = IP(dst="127.0.0.1")/xcpLayer

	return ipLayer
	

	
def makeFieldObjects(packet,basemodelname):
	global fieldObjectsArray
	global BTNEditedBG, BTNNotEditedBG
	fieldObjectsArray = []
	lyrs= []
	lyrs = findLayers(packet)
	#print "Making Objects"
	#print "   Layers found: "+repr(lyrs)
	count = 0
	for lyr in lyrs:
		#print layer
		layer = packet.getlayer(lyr)
		
		if basemodelname in lyr:
			editor = scapyCustomizerTBMG.scapyCustomizerTBMG(os.path.join("models",basemodelname,"scapy","model",lyr+".py"))
		else:
			editor = None
		
		for fdesc in layer.fields_desc:
			
				field_value = ifhex((getattr(layer,fdesc.name)))
				#print field_value
				if field_value == None:
					field_value = "None"
					
				hasedits = (editor.hasedits(fdesc.name) if editor is not None else False)
				
				fieldob = fieldObj(fdesc.name, field_value, lyr)
				fieldob.setTKName(Label(page3,text=fdesc.name))
				default_value = StringVar(page3, value=field_value)
				
				fieldob.setTKValue(Entry(page3, textvariable=default_value))
				fieldob.setTKfieldNoneBTN(Button(page3, text='N', padx=0,pady=0, command=lambda fo=fieldob: updateGuiFields(fo,None) ))
				fieldob.setTKfieldDefaultBTN(Button(page3, text='D', padx=0,pady=0, command=lambda fo=fieldob,fv=field_value: updateGuiFields(fo,fv)  ))
				fieldob.setTKSynth(Entry(page3, state="readonly"))
				if (lyr == 'TCP' or lyr == 'UDP' or lyr == 'IP'):
					fieldob.setTKAdvEditBTN(Label(page3,text=""))
				else:
					btnedit = Button(page3,text="Edit",pady=0,command=lambda fob=fieldob,b=basemodelname:AdvEdit(fob,b))
					btnedit.config(background=(BTNEditedBG if hasedits else BTNNotEditedBG))
					fieldob.setTKAdvEditBTN(btnedit)
				#print "field objects made"
				#fieldob.toString()
				fieldObjectsArray.append(fieldob)
		count += 1

def AdvEdit(fieldob,basemodelname):
	nb.tab(page3_5,state=NORMAL)
	
	for wid in page3_5.winfo_children():
		wid.destroy()
	
	layer = fieldob.layer
	field = fieldob.name
	editor = scapyCustomizerTBMG.scapyCustomizerTBMG(os.path.join("models",basemodelname,"scapy","model",layer+".py"))
	edits = editor.getedits(field)
	options = editor.getoptions(field)
	edit_args = edits['LOGIC'].split(" ")

	controlpanel = Frame(page3_5)
	controlpanel.grid(row=0,column=0,rowspan=20,sticky=N)
	
	layerlabel = Label(controlpanel,text="Layer:")
	layerlabel.grid(row=0,column=0,sticky=W)
	layerdisp  = Label(controlpanel,text=layer)
	layerdisp.grid(row=0,column=1,sticky=W)
	
	fieldlabel = Label(controlpanel,text="Field:")
	fieldlabel.grid(row=1,column=0,sticky=W)
	fielddisp  = Label(controlpanel,text=field)
	fielddisp.grid(row=1,column=1,sticky=W)

	valuepanel = Frame(page3_5)
	valuepanel.grid(row=0,column=5,rowspan=20,sticky=N)
	
	colsep = Frame(page3_5,width=25)
	colsep.grid(row=0,column=4)
	
	vprow = 0
	rawlabel = Label(valuepanel,text="Current RAW value(s):")
	rawlabel.grid(row=vprow,column=0,columnspan=2,sticky=W)
	vprow += 1
	rowdisp = Label(valuepanel,text=edits['LOGIC'])
	rowdisp.grid(row=vprow,column=0,columnspan=2,sticky=W)
	vprow += 1

	if '_AFTER' in options:
		runlabel = Label(valuepanel,text=options['_AFTER']['title']+":")
		runlabel.grid(row=vprow,column=0,sticky=W)
		options['_AFTER']['_var'] = StringVar()
		options['_AFTER']['_var'].set(edits['AFTER'])
		options['_AFTER']['_field'] = OptionMenu(valuepanel,options['_AFTER']['_var'],*(options['_AFTER']['source']))
		options['_AFTER']['_field'].configure(pady=0)
		options['_AFTER']['_field'].grid(row=vprow,column=1,sticky=W)
		vprow += 1

	options["_chosen"] = StringVar()
	options["_chosen"].set(edit_args[0])

	for i in options:
		if i[0:1] == "_":
			continue
		
		options[i]['_spacer'] = Label(valuepanel,text=" ")
		options[i]['_spacer'].grid(row=vprow,column=0,columnspan=2)
		vprow += 1
		
		options[i]['_sel'] = Radiobutton(valuepanel,text=i,variable=options["_chosen"],value=i)
		options[i]['_sel'].grid(row=vprow,column=0,columnspan=4,sticky=W)
		vprow += 1
		
		options[i]['_frame'] = Frame(valuepanel)
		options[i]['_frame'].grid(row=vprow,column=0,columnspan=5,sticky=W)
		vprow += 1

		orow = 0
		options[i]['_help'] = Button(options[i]['_frame'],text='?',pady=0,command=lambda t=i,h=options[i]['help']:alertpop(t,h))
		options[i]['_help'].grid(row=orow,column=0,sticky=W)
		options[i]['_helplabel'] = Label(options[i]['_frame'],text='About '+i)
		options[i]['_helplabel'].grid(row=orow,column=1,sticky=W)
		orow += 1
		for o in options[i]:
			if o[0:1] == "_" or o in ['help']:
				continue
			
			options[i][o]['_label'] = Label(options[i]['_frame'],text=options[i][o]['title'])
			options[i][o]['_label'].grid(row=orow,column=1,sticky=W)
			
			if 'help' in options[i][o]:
				options[i][o]['_help'] = Button(options[i]['_frame'],text='?',pady=0,command=lambda t=i+" "+options[i][o]['title'],h=options[i][o]['help']:alertpop(t,h))
				options[i][o]['_help'].grid(row=orow,column=0)
			
			value = str(""+str(options[i][o]['default']))
			if edit_args[0] == i:
				if o in edits:
					value = edits[o]
				if 'arg' in o:
					arg = int(o[3:])
					if len(edit_args) > arg:
						value = edit_args[arg]

			if options[i][o]['type'] == 'select':
				options[i][o]['_selvar'] = StringVar()
				options[i][o]['_selvar'].set(value)
				options[i][o]['_field'] = OptionMenu(options[i]['_frame'],options[i][o]['_selvar'],options[i][o]['_selvar'].get(),*(options[i][o]['source']))
				options[i][o]['_field'].configure(pady=0)
				options[i][o]['_field'].grid(row=orow,column=2,sticky=W)
				options[i][o]['_get'] = lambda v=options[i][o]['_selvar']: v.get()
				orow += 1
			elif options[i][o]['type'] == 'textarea':
				options[i][o]['_field'] = Text(options[i]['_frame'],width=40,height=5,wrap=NONE)
				options[i][o]['_field'].grid(row=orow,column=2,sticky=W)
				options[i][o]['_scrolly'] = Scrollbar(options[i]['_frame'],command=options[i][o]['_field'].yview)
				options[i][o]['_scrolly'].grid(row=orow,column=3,sticky=N+S+W)
				orow += 1
				options[i][o]['_scrollx'] = Scrollbar(options[i]['_frame'],command=options[i][o]['_field'].xview,orient=HORIZONTAL)
				options[i][o]['_scrollx'].grid(row=orow,column=2,sticky=N+E+W)
				orow += 1
				options[i][o]['_field'].configure(yscrollcommand=options[i][o]['_scrolly'].set,xscrollcommand=options[i][o]['_scrollx'].set)
				options[i][o]['_field'].insert(END,str(value))
				options[i][o]['_get'] = lambda f=options[i][o]['_field']: f.get(1.0,END)
			elif options[i][o]['type'] == 'text':
				options[i][o]['_textvar'] = StringVar()
				options[i][o]['_textvar'].set(value)
				options[i][o]['_field'] = Entry(options[i]['_frame'],textvariable=options[i][o]['_textvar'])
				options[i][o]['_field'].grid(row=orow,column=2,sticky=W)
				orow += 1
				options[i][o]['_get'] = lambda v=options[i][o]['_textvar']: v.get()
			else:
				print "ERROR, unknown field type: "+options[i][o]['type']
				return

	savebtn = Button(controlpanel,text="Save and Close",command=lambda fob=fieldob,b=basemodelname,o=options: SaveAdvEdit(fob,b,o))
	savebtn.grid(row=30,column=0,columnspan=2,sticky=S)
	cancelbtn = Button(controlpanel,text="Close without saving",command=CloseAdvEdit)
	cancelbtn.grid(row=31,column=0,columnspan=2,sticky=S)
	
	nb.select(page3_5)

def alertpop(title,mlinestring):
	print title
	print mlinestring
	tkMessageBox.showinfo(title,mlinestring)

def SaveAdvEdit(fieldob,basemodelname,options):
	global BTNEditedBG, BTNNotEditedBG

	layer = fieldob.layer
	field = fieldob.name
	editor = scapyCustomizerTBMG.scapyCustomizerTBMG(os.path.join("models",basemodelname,"scapy","model",layer+".py"))

	#TODO: save
	edits = {}
	if options['_chosen'] != "":
		i = options['_chosen'].get()
		edit_args = [i]
		for o in options[i]:
			if o[0:1] == "_" or "_field" not in options[i][o]:
				continue

			value = options[i][o]['_get']()

			if "arg" in o:
				a = int(o[3:])
				while len(edit_args) < a+1:
					edit_args.append("")
				edit_args[int(o[3:])] = value
			else:
				edits[o] = value
		edits["LOGIC"] = " ".join(edit_args)

	if "_AFTER" in options:
		edits["AFTER"] = options['_AFTER']['_var'].get()

	if "LOGIC" in edits:
		editor.saveEdits(fieldob.name,edits)

	mods = editor.hasedits(field)
	fieldob.TKAdvEditBTN.configure(background = BTNEditedBG if mods else BTNNotEditedBG)
	
	ReloadProtocol(fieldob.layer)
	
	CloseAdvEdit()

def CloseAdvEdit():
	nb.select(page3)
	nb.tab(page3_5,state=DISABLED)

def ReloadProtocol(protoname):
	global mod_model, mod_class, packet

	#TODO: reload the class, and reinstantiate

	reload(mod_model)
	mod_class = getattr(mod_model,protoname)
	
	sub = packet
	while type(sub.payload).__name__ != protoname:
		sub = sub.payload
	
	old = sub.payload
	sub.payload = mod_class()
	sub.payload.cloner(old)

def findLayers(packet):
	layerindex = ["IP", "TCP", "UDP"]
	lyrs = []
	count = 0
	for layer in layerindex:
		lyr = packet.getlayer(count)
		if lyr:
			lyrs.append(lyr.name)
		count += 1
	return lyrs
	

def getProtoLayerSize():##for dependencies usage
	global ipLayer, layers, handletcp, datalayer
	
	ipLayer = None

	count = 2
	for lindex, layer in enumerate(layers[::-1]):

		if ipLayer == None:
			if count  == 2:
				datalayer=layer
		count = count - 1
def showmodeldata(name, modeltype, connecttype):
	global show
	
	old_stdout, sys.stdout = sys.stdout, BytesIO()
	packet = buildscapyproto(name,modeltype,connecttype)
	if show != None:
		show.delete(1.0, END)
	else:
		show = Text(page2)
	
	show.grid(sticky="W")
	#packet = a.show()
	packet.show2()
	try:
		output = sys.stdout.getvalue()
	finally:
		sys.stdout = old_stdout
	show.insert(END, output)
	#page2.configure(height=root_tab.winfo_reqheight())
    
def modifymodeldata(name, modeltype, connecttype):
	global fieldObjectsArray, tcpEntry, destEntry, packet
	global BTNEditedBG,BTNNotEditedBG
	###clear page 3 screen to update labeling###
	for child in page3.winfo_children():
		child.destroy()
	rowcount = 1
	protoffset = 5;
	packet = buildscapyproto(name,modeltype,connecttype)
	print "before"
	packet.show()
	makeFieldObjects(packet,name)
	
	lyrs = findLayers(packet)
	TCProwOffset = 0
	for layer in lyrs:
		if "TCP" == layer:
			TCProwOffset = rowcount+1
		if name in layer:
			editor = scapyCustomizerTBMG.scapyCustomizerTBMG(os.path.join("models",name,"scapy","model",layer+".py"))
			fakefieldob = fieldObj('_GENERAL_',0,layer)
			genedit = Button(page3,text="Edit",command=lambda fb=fakefieldob,b=name: AdvEdit(fb,b) )
			genedit.configure(pady=0,background=(BTNEditedBG if editor.hasedits("_GENERAL_") else BTNNotEditedBG))
			genedit.grid(row=rowcount,column=-1+protoffset,sticky=E)
			fakefieldob.setTKAdvEditBTN(genedit)
		layerLabel = Label(page3,text="     "+layer+"     ", font = "bold")
		layerLabel.grid(row=rowcount, column = 0+protoffset, sticky=W )
		layerLabel.configure(background='#aaaaaa')
		rowcount += 1
		for field in fieldObjectsArray:
			if field.layer==layer:
				field.TKfieldName.grid( row=rowcount, column = 0+protoffset, sticky=W)
				field.TKfieldValue.grid(row=rowcount, column = 1+protoffset, sticky=W)
				field.TKfieldNoneBTN.grid(row=rowcount,column= 2+protoffset, sticky=W)
				field.TKfieldDefaultBTN.grid(row=rowcount,column=3+protoffset,sticky=W)
				field.TKfieldSynth.grid(row=rowcount, column = 4+protoffset, sticky=W)
				field.TKAdvEditBTN.grid(row=rowcount, column = -1+protoffset, sticky=E)
				rowcount += 1
				
	buttonsRoffset = 1 #rowcount
	buttonsCoffset = 0
	
	ButtonsPanelSenders = Frame(page3)
	ButtonsPanelSenders.grid(row=buttonsRoffset,column=buttonsCoffset,columnspan=protoffset,rowspan=5)
	#row and column positions were originally for inserting onto page3 grid directly, but still work after being put in a container Frame
	updateButton = Button(ButtonsPanelSenders, text = "Update", command = lambda: updatemodeldata2())
	updateButton.grid(row=buttonsRoffset+1, column=0+buttonsCoffset, sticky=S)
	sendButton = Button(ButtonsPanelSenders, text = "Send", command = lambda: sendpacket2())
	sendButton.grid(row=buttonsRoffset+2, column=0+buttonsCoffset, sticky=S)
	
	TCP = packet.getlayer('TCP')
	TCProwOffset = max(buttonsRoffset+2,TCProwOffset)
	if TCP:
		ButtonsPanelTCP = Frame(page3)
		ButtonsPanelTCP.grid(row=TCProwOffset,column=buttonsCoffset,columnspan=protoffset,rowspan=10)
		#row and column positions were originally for inserting onto page3 grid directly, but still work after being put in a container Frame
		destLabel=Label(ButtonsPanelTCP, text="Dst IP:")
		destLabel.grid(row=TCProwOffset+0, column=0+buttonsCoffset,sticky=W)
		destEntry = Entry(ButtonsPanelTCP)
		destEntry.grid(row=TCProwOffset+1, column=0+buttonsCoffset,sticky=W)
		tcpPortLabel = Label(ButtonsPanelTCP,text="Port:")
		tcpPortLabel.grid(row=TCProwOffset+2, column=0+buttonsCoffset,sticky=W)
		tcpEntry = Entry(ButtonsPanelTCP)
		tcpEntry.grid(row=TCProwOffset+3, column=0+buttonsCoffset,sticky=W)
		tcpButton = Button(ButtonsPanelTCP, text = "Auto TCP Connection", command = lambda: handleTCP())
		tcpButton.grid(row=TCProwOffset+4,column=0+buttonsCoffset, sticky=W)
		mantcp = Button(ButtonsPanelTCP, text = "Manual TCP Connection", command = manualTCP)
		mantcp.grid(row=TCProwOffset+5, column=0+buttonsCoffset, sticky=W)
		etcpButton = Button(ButtonsPanelTCP, text = "End TCP Handshake", command = closeTCP)
		etcpButton.grid(row=TCProwOffset+6,column=0+buttonsCoffset, sticky=W)
	nb.select(page3)

	
def ifhex(fieldname):
	if isinstance(fieldname, (int, long)):
		return hex(fieldname)
	else:
		return repr(fieldname)
		
def displayDependencyOptions():
	
	##Todo: looking for a way to add a checkbox next to each field in the data layer
	global formdescs
	#print str(formdescs)
	count = 2
	linenum= 0
	for layer in layers:
		linenum += 1
		print linenum
		if count ==0:
			for fdesc in layer.fields_desc:
				linenum +=1
				print linenum
				print "Checking if data layer"+fdesc.name
		count = count -1
def makeIP():
	print "making IP"
	global fieldObjectsArray, packet
	ip = IP()
	ip.name=packet.name
	
	return ip
	
def sendpacket2():
	global mystream, handletcp, autoTCP, packet
	
	print "###Before TEST###"
	packet.show()
	layers = findLayers(packet)
	if len(layers)==3:
		dataLayer = packet.getlayer(layers[2])
	else:
		dataLayer = packet.getlayer(layers[1])
	print "this should be the data layer: " + str(dataLayer)
	#dataLayer = packet.getlayer(layers[2])
	#print "this is dataLayer"
	#dataLayer.show()
	#print "this is ipLayer"
	ipLayer = makeIP()
	
	print "###TEST###"
	print "ipLayer.show = :"
	ipLayer.show()
	#print "packet.show = :"
	#packet.show()
	if handletcp==True:
		datapacket = ipLayer/autoTCP/dataLayer
		print "###showing compiled version of packet"
		datapacket.show2()
		
		FlagActualSend(True)
		mystream.send(datapacket)##ipLayer
		FlagActualSend(False)
		#print "this is what we just sent"
		#datapacket.show()

	else:
		FlagActualSend(True)
		send(packet)
		FlagActualSend(False)
	#print "seq sent is: "+str(mystream.ack)
	
	print "Following Message Sent"
	packet.show2()
	
	autoScrape(packet)

def autoScrape(packet):  #writes sent values to the readonly GUI elements
	global fieldObjectsArray
	global SynthMatchBG, SynthDiffBG
	
	packetinfo = PacketScraper(packet)
	
	for field in fieldObjectsArray:
		if field.layer not in packetinfo:
			continue
		if field.name not in packetinfo[field.layer]:
			continue
		
		resval = packetinfo[field.layer][field.name]
		setval = field.TKfieldValue.get()
		same = SafeCompareEqual(setval,resval)
		
		field.TKfieldSynth.config(state=NORMAL)
		field.TKfieldSynth.delete(0,END)
		field.TKfieldSynth.insert(0,resval)
		field.TKfieldSynth.config(state="readonly",readonlybackground=(SynthMatchBG if same else SynthDiffBG))
		

def PacketScraper(packet):  #creates an associative collection of values from the packet
	
	asobj = OrderedDict()
	
	capture = StringIO()
	old_stdout = sys.stdout
	sys.stdout = capture
	packet.show2()
	sys.stdout = old_stdout
	asstr = capture.getvalue()
	
	layer = ""
	for line in asstr.split("\n"):
		if line[0:3] == "###":
			layer = line[5:-5].strip()
			asobj[layer] = OrderedDict()
			continue
		if "=" not in line:
			continue
		field,value = line.split(" = ",1)
		field = field.strip()
		asobj[layer][field] = value
	
	# orignially wanted to go through packets, and find any "synthfields"
	# adding attributes nightmare: https://github.com/secdev/scapy/issues/343
	# so had to settle on using print, and capturing from above text logic
	
	return asobj
	
def SafeCompareEqual(a,b):
	
	if (a == '' or a == '[]' or a == '{}' or a == '0x0') and (b == '' or b == '[]' or b == '{}' or b == '0x0'):
		return True
	
	if ("'"+str(a)+"'" == b or a == "'"+str(b)+"'"):
		return True
	
	try:
		return (eval(a)==eval(b))
	except:
		return False


def handleTCP():
	global handletcp, srcip, mystream, autoTCP, fieldObjectsArray, packet, mysocket
	f= None
	handletcp=True
	dstIP = destEntry.get()
	dstport = tcpEntry.get()
	dstport=eval(dstport)
	autoTCP = TCP(dport=dstport)
	mysocket=socket.socket()
	mysocket.connect((dstIP, dstport))
	mystream=StreamSocket(mysocket)
	dport = getField("dport")
	dst = getField("dst")
	proto = getField("proto")
	updateGuiFields(dst, dstIP)
	updateGuiFields(proto,0x06)
	updateGuiFields(dport, dstport)
	setattr(packet['IP'],'dst',dstIP)
	#print dstport
	#print dstIP
	#createHandShake(dstIP, dstport, sport)
def closeTCP():
	global mysocket
	#mysocket.shutdown(SHUT_RDWR)
	mysocket.close()
	
def updateObjectField(field, updateValue):
	global fieldObjectsArray
	for field in fieldObjectsArray:
		if field.name == field:
			field.setValue = updateValue
			updateGuiFields(field, updateValue)
	
	
def manualTCP():
	global srcip
	subprocess.call(["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP" ])
	#iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	subprocess.call(["iptables", "-L"])
	#iptables -L
	sport = random.randint(1024, 65535)
	dstIP = destEntry.get()
	dstport = tcpEntry.get()
	dstport=eval(dstport)
	updateField("Transport","sport", sport)
	updateField("Transport","dport", dstport)
	updateField("IP","dst", dstIP)
	updateField("Transport","flags", 0x18)
	updateField("Transport", "seq", 12346)
	updateField("IP","proto",0x06)
	
	ip = IP(src=srcip, dst=dstIP)
	SYN = TCP(sport=sport, dport=dstport, flags="S", seq=12345)
	SYNACK=sr1(ip/SYN)
	my_ack = SYNACK.seq+1
	ACK=TCP(sport = sport, dport=dstport, flags="A", seq=12346, ack=my_ack)
	updateField("Transport","ack", my_ack)
	
	FlagActualSend(True)
	send(ip/ACK)
	FlagActualSend(False)

def getField(fieldName):
		for field in fieldObjectsArray:
			if field.name == fieldName:
				return field
def updateField(layerID,fieldname, updateValue):
	#global layers, layerindex
	
	for lindex, layer in enumerate(layers):
		if layerindex[lindex] != layerID:
			continue
		#for field in fieldObjectsArray:
			##print "looking for port and ip fields in layer "+str(layer)+": "+field.name
			#if field.name != fieldname:
				#continue
			
		for fdesc in layer.fields_desc:
			if fdesc.name == fieldname:
				print "updating "+fdesc.name +"w/ updateValue: "+ str(updateValue)
				setattr(layer,fdesc.name,updateValue)
				
				#updateGuiFields(field, updateValue, layer)
	
	rebuildIPlayer()
	
	#efresheditmodeldata()
def updatemodeldata2():
	global fieldObjectsArray, packet
	print "\n \n Original Values \n \n"
	packet.show()
	lyrs = findLayers(packet)
	for field in fieldObjectsArray:
		updateValue = field.TKfieldValue.get()
		l= lyrs.index(field.layer)
		if updateValue != field.value:
			print updateValue
			#exec("updateValue="+updateValue)
			updateValue = eval(str(updateValue))
			fieldname = field.name
			noneObject = None
			if field.name != "options":
				print "updating "+"."+fieldname+" with " +str(updateValue)
				print field.layer
				setattr(packet[field.layer],field.name,updateValue)
				updateGuiFields(field, updateValue)
		field.setValue = updateValue
		

	print "\n \n New Values \n \n"
	packet.show()
	
	#print "\n\nfinal packet:\n"
	#packet.show2()

def updateGuiFields(field, updateValue):
	field_data = ifhex(updateValue)
	if field_data ==None:
		field_data = "None"
	field.TKfieldValue.delete(0, END)
	field.TKfieldValue.insert(0, field_data)
	field.setValue = updateValue

def FlagActualSend(onoff):
	fname = os.path.join(os.path.expanduser("~"),".TBMG_ActualSend")
	if onoff:
		with open(fname,"a") as f:
			os.utime(fname,None)
	else:
		os.remove(fname)

#######################################################################################
#######################################################################################
#before my time ^^^^^^ - the4960
#######################################################################################
#######################################################################################
root_widgit=None
root_tab=None


# http://code.activestate.com/recipes/580726-tkinter-notebook-that-fits-to-the-height-of-every-/
class AutoresizedNotebook(ttk.Notebook):
    
    def __init__(self, master=None, **kw):
        ttk.Notebook.__init__(self, master, **kw)
        self.bind("<<NotebookTabChanged>>", self._on_tab_changed)
    
    def _on_tab_changed(self, event):
        global root_widgit
        global root_tab
        event.widget.update_idletasks()
        tab = event.widget.nametowidget(event.widget.select())
        event.widget.configure(height=tab.winfo_reqheight())
        event.widget.configure(width=tab.winfo_reqwidth())
        root_widgit = event.widget
        root_tab = tab


# http://code.activestate.com/recipes/580726-tkinter-notebook-that-fits-to-the-height-of-every-/
class AutoresizedNotebookChild(ttk.Notebook):
    
    def __init__(self, master=None, **kw):
        ttk.Notebook.__init__(self, master, **kw)
        self.bind("<<NotebookTabChanged>>", self._on_tab_changed)
    
    def _on_tab_changed(self, event):
        global root_widgit
        #TODO handle resize height on tab change!!!!!
        #global applicationAutoresizedNotebookChild
        print (dir(self))
        #if application:
        #    print application
        #if application.traffic_tab.tab(self.tbmg.traffic_tab.select(), 'text') == 'PCAP':
        
        event.widget.update_idletasks()
        root_widgit.configure(height=root_tab.winfo_reqheight())
        root_widgit.configure(width=root_tab.winfo_reqwidth())


def updateResize(event):
    global skip_resize
    global init_req_h
    global init_req_v
    if skip_resize < 100:
        skip_resize += 1
        return
    #'''
    while 1:
        try:
            if not init_req_h:
                init_req_h = page_tbmg.winfo_reqwidth()
                for e in expand_h:
                    e.config(width=1)
                skip_resize=0
                break
            if event.width < init_req_h:
                for e in expand_h:
                    e.config(width=1)
                skip_resize=0
                break
            for e in expand_h:
                if e.cget('width') < event.width-10 or e.cget('width') > event.width + 10:
                    print 'resize w'
                    skip_resize=0
                    e.config(width=event.width)
        except Exception as e:
            print e
            skip_resize = 0
        break
    #'''
    try:
        if not init_req_v:
            init_req_v = page_proxy.winfo_reqheight()
            for e in expand_v:
                e.config(height=1)
            skip_resize=0
            return
        if event.height < init_req_v:
            for e in expand_v:
                e.config(height=1)
            skip_resize=0
            return
        for e in expand_v:
            if e.cget('height') < event.height-10 or e.cget('height') > event.height + 10:
                print 'resize h'
                skip_resize=0
                e.config(height=event.height)
    except Exception as e:
        print e
        skip_resize = 0
    print '---------------------------------------------'


def on_closing():
    app.restoreIPTables()
    try:
        if app.scapybridgeS.status:
            app.scapybridgeS.proxyToggle()
        if app.scapybridgeR.status:
            app.scapybridgeR.proxyToggle()
        app.scapybridgeS.display_lock.release()
        app.scapybridgeR.display_lock.release()
        app.scapybridgeR.display_lock.release()
        print 'proxy is:', app.scapybridgeS.status or app.scapybridgeR.status
    except:
        pass
    try:
        app.scapybridgeS.intercepter.stop()
        app.scapybridgeR.intercepter.stop()
        print 'stop interceptors'
    except Exception as e:
        print e, 'coundt stop interceptors'
    root.destroy()
    for t in threading.enumerate():
        try:
            print 'joining thread running:', t.name
            t.join(timeout=.05)
        except:
            pass
    print 'donezo'
    sys.exit()


expand_h=[]
expand_v=[]
skip_resize = 0
init_req_h = 0
init_req_v = 0

packet = None
ipLayer = None
show = None
tcpEntry=None
destEntry=None
srcip=None
mystream=None
datalayer=None
fieldObjectsArray = []
onlyView = False
mysocket=None
handletcp = False
autoTCP = None
mod_model = None
mod_class = None
firstField = 2
formFields = []
formdescs = []
layers = []
layerindex = []
fieldArray = []
hidden = True
root = themed_tk.ThemedTk() #Tk()
root.set_theme('elegance')
root.title("Traffic Based Model Generator")
#icon
imgicon = ImageTk.PhotoImage(file='/root/tbmg/bin/logo.png')
root.tk.call('wm', 'iconphoto', root._w, imgicon)
#resize stuff
#root.bind("<Configure>", updateResize)
#top = root.winfo_toplevel()
#top.rowconfigure(0, weight=1)
#top.columnconfigure(0, weight=1)
#root.rowconfigure(0, weight=1)
#root.columnconfigure(0, weight=1)
root.resizable(width=False, height=False)
#resize stuff
root.protocol("WM_DELETE_WINDOW", on_closing)

SynthMatchBG = "#ddddee"
SynthDiffBG  = "#ffffcc"
BTNEditedBG = "#eedddd"
BTNNotEditedBG = None #uses default color



nb0 = AutoresizedNotebook(root)
nb0.grid_rowconfigure(0,weight=1)
nb0.grid_columnconfigure(0,weight=1)
nb0.grid(row=0, column=0,sticky='NESW')

page_tbmg = ttk.Frame(nb0)
nb0.add(page_tbmg, text='TBMG', sticky='NESW')

page_proxy = ttk.Frame(nb0)
nb0.add(page_proxy, text='ScapyProxy', sticky='NESW')

nb = AutoresizedNotebookChild(page_tbmg)
nb.grid(row=0, column=0, columnspan=50, rowspan=49, sticky='NESW')

# Adds tab 1 of the notebook
page1 = ttk.Frame(nb)
nb.add(page1, text='Model Generation', sticky='NESW')

# Adds tab 2 of the notebook
page2 = ttk.Frame(nb)
nb.add(page2, text='View Model', sticky='NESW')

page3 = ttk.Frame(nb)
nb.add(page3, text='Edit Model', sticky='NESW')

page3_5 = ttk.Frame(nb)
nb.add(page3_5, text='Adv. Field', state=DISABLED, sticky='NESW')

page4 = ttk.Frame(nb)
nb.add(page4, text='Create Dissector', sticky='NESW')


nb2 = AutoresizedNotebookChild(page_proxy)
nb2.grid(row=0, column=0, columnspan=50, rowspan=49, sticky='NESW')

page5 = ttk.Frame(nb2)
nb2.add(page5, text='Scapy Proxy', sticky='NESW')

page6 = ttk.Frame(nb2)
nb2.add(page6, text="Fuzzer", state=DISABLED, sticky='NESW')

page7 = ttk.Frame(nb2)
nb2.add(page7, text="Hooks", sticky='NESW')

page8 = ttk.Frame(nb2)
nb2.add(page8, text="Settings", sticky='NESW')

#page8 = ttk.Frame(nb2)
#nb2.add(page6, text="Hook", state=DISABLED, sticky='NESW')

app = Application(root)
root.mainloop()

