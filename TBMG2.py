#!/usr/bin/python2
from Tkinter import *
from tkFileDialog import askopenfilename
import tkMessageBox
from jinja2 import Template
from io import BytesIO
import ttk
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
from scapyProxy.scapy_bridge import *
import tkFileDialog
import threading
from scapyProxy.GuiUtils import VerticalScrolledFrame

class Application(Frame):
    def __init__(self, master):
        """initialize the frame"""
        Frame.__init__(self,master)
        self.grid()
        self.create_widgets()

    def create_widgets(self):
        self.protocol = Label(page1, text = "Protocol Name:")
        self.protocol.grid(row = 1, column = 0,  sticky = W)
        self.proto = Entry(page1)
        self.proto.grid(row = 1, column = 1,  sticky = W)


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
        ###########################################################
        
        self.scapybridge = ScapyBridge(self)
        
        self.startproxy = Button(page5, text='Proxy Toggle', command = self.scapybridge.proxyToggle)
        self.startproxy.grid(row=0, column=0)
        
        self.intercept = Button(page5, text='Intercept On', command = self.scapybridge.interceptToggle)
        self.intercept.grid(row=0, column=1)

        self.queue = Button(page5, text='Network queue')
        self.queue.grid(row=0, column=2)
        
        
        def file_save():
            #https://stackoverflow.com/questions/19476232/save-file-dialog-in-tkinter
            f = tkFileDialog.asksaveasfile(mode='w', defaultextension=".pcap")
            if f is None:  # asksaveasfile return `None` if dialog closed with "cancel".
                return
            self.scapybridge.pcapfile = f.name
            print 'using',f.name
            f.close()
        self.savepcap = Button(page5, text='Save to PCAP', command=file_save)
        self.savepcap.grid(row=0, column=3)
        
        self.rawview = Button(page5, text='Raw', command=self.scapybridge.sendRawUpdate)
        self.rawview.grid(row=1, column=0)
        self.disectview = Button(page5, text='Dissected', command=self.scapybridge.sendDisectUpdate)
        self.disectview.grid(row=1, column=1)
        
        def setFilter():
            self.scapybridge.filter = self.proxyfilter.get()
            print 'using filter:', self.scapybridge.filter
        self.defaultproxyfiltertext = Button(page5, text="Filter:", command=setFilter)
        self.defaultproxyfiltertext.grid(row=2, column=0)
        self.proxyfilter = Entry(page5)
        self.proxyfilter.bind("<Return>", setFilter)
        self.proxyfilter.grid(row=2, column=1)
        
        self.rawtext = Text(page5, height=50, width=55)
        self.rawtextscroll = Scrollbar(page5)
        self.rawtextscroll.config(command=self.rawtext.yview)
        self.rawtext.config(yscrollcommand=self.rawtextscroll.set)
        self.rawtext.grid(row=3, column=0)
        self.rawtextscroll.grid(row=3, column=1)
        self.rawtext.insert(END,'RAWVIEW\n---\n')
        
        #for not intercepting
        self.disecttext = Text(page5, height=50, width=55)
        self.disecttextscroll = Scrollbar(page5)
        self.disecttextscroll.config(command=self.disecttext.yview)
        self.disecttext.config(yscrollcommand=self.disecttextscroll.set)
        self.disecttext.grid(row=3, column=2)
        self.disecttextscroll.grid(row=3, column=3)
        self.disecttext.insert(END, 'DISECT\n---\n')
        self.disectlist = None
        self.disectLable = None
        '''
        #for intercepting
        self.disectlist = VerticalScrolledFrame(page5,height=100,width=50)
        self.disectlist.grid(row=3, column=2)
        self.disectLable = Label(self.disectlist.interior, text='DISECT VIEW\n----\n')
        self.disectLable.grid(row=0,column=0)
        '''
        self.send = Button(page5, text='Send')
        self.send.grid(row=4, column=0)
        self.drop = Button(page5, text='Drop', command=self.update())
        self.drop.grid(row=4, column=1)
        
        self.page5 = page5
        


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
root = Tk()
root.title("Traffic Based Model Generator")
SynthMatchBG = "#ddddee"
SynthDiffBG  = "#ffffcc"
BTNEditedBG = "#eedddd"
BTNNotEditedBG = None #uses default color

nb = ttk.Notebook(root)
nb.grid(row=1, column=0, columnspan=50, rowspan=49, sticky='NESW')

# Adds tab 1 of the notebook
page1 = ttk.Frame(nb)
nb.add(page1, text='Model Generation')

# Adds tab 2 of the notebook
page2 = ttk.Frame(nb)
nb.add(page2, text='View Model')

page3 = ttk.Frame(nb)
nb.add(page3, text='Edit Model')

page3_5 = ttk.Frame(nb)
nb.add(page3_5, text='Adv. Field', state=DISABLED)

page4 = ttk.Frame(nb)
nb.add(page4, text='Create Dissector')

page5 = ttk.Frame(nb)
nb.add(page5, text='Scapy Proxy')

app = Application(root)
root.mainloop()

