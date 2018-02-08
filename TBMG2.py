from Tkinter import *
from tkFileDialog import askopenfilename
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
        
        self.protnames = os.listdir(".")
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
	models = os.listdir(modelname+"/scapy/model/")
	modelChosen = StringVar()
	connectChosen = StringVar()
	path1 = modelname+"/__init__.py"
	path2 = modelname+"/scapy/__init__.py"

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
	modelpath = name + "/scapy/"
	model_strip = modeltype.strip(".py")

	mod_model = importlib.import_module(name+".scapy.model."+model_strip)
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
	

				
def makeFieldObjects(packet):
	global fieldObjectsArray
	fieldObjectsArray = []
	lyrs= []
	lyrs = findLayers(packet)
	#print "Making Objects"
	#print "   Layers found: "+repr(lyrs)
	count = 0
	for lyr in lyrs:
		#print layer
		layer = packet.getlayer(lyr)
		for fdesc in layer.fields_desc:

				field_value = ifhex((getattr(layer,fdesc.name)))
				#print field_value
				if field_value == None:
					field_value = "None"
				fieldob = fieldObj(fdesc.name, field_value, lyr)
				fieldob.setTKName(Label(page3,text=fdesc.name))
				default_value = StringVar(page3, value=field_value)
				fieldob.setTKValue(Entry(page3, textvariable=default_value))
				#print "field objects made"
				#fieldob.toString()
				fieldObjectsArray.append(fieldob)
		count += 1


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
	###clear page 3 screen to update labeling###
	for child in page3.winfo_children():
		child.destroy()
	rowcount = 1
	packet = buildscapyproto(name,modeltype,connecttype)
	print "before"
	packet.show()
	makeFieldObjects(packet)
	
	lyrs = findLayers(packet)
	for layer in lyrs:
		layerLabel = Label(page3,text=layer, font = "bold")
		layerLabel.grid(row=rowcount, column = 1, sticky=E)
		rowcount += 1
		for field in fieldObjectsArray:
			if field.layer==layer:
				field.TKfieldName.grid(row=rowcount, column=0, sticky=W)
				field.TKfieldValue.grid(row=rowcount, column =1, sticky=W)
				rowcount += 1
	updateButton = Button(page3, text = "Update", command = lambda: updatemodeldata2())
	updateButton.grid(row=rowcount+1, sticky=W)
	TCP = packet.getlayer('TCP')
	if TCP:
		tcpButton = Button(page3, text = "Auto TCP Connection", command = lambda: handleTCP())
		tcpButton.grid(row=rowcount+2,column=0, sticky=W)
		tcpPortLabel = Label(page3,text="Port:")
		tcpPortLabel.grid(row=rowcount+2, column=1)
		tcpEntry = Entry(page3)
		tcpEntry.grid(row=rowcount+2, column=2)
		destLabel=Label(page3, text="Dst IP")
		destLabel.grid(row=rowcount+3, column=1)
		destEntry = Entry(page3)
		destEntry.grid(row=rowcount+3, column=2)
		mantcp = Button(page3, text = "Manual TCP Connection", command = manualTCP)
		mantcp.grid(row=rowcount+3,sticky=W)
		etcpButton = Button(page3, text = "End TCP Handshake", command = closeTCP)
		etcpButton.grid(row=rowcount+4,sticky=W)
	sendButton = Button(page3, text = "Send", command = lambda: sendpacket2())
	sendButton.grid(sticky=W)	
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
	print "packet.show = :"
	#packet.show()
	if handletcp==True:
		datapacket = ipLayer/autoTCP/dataLayer
		print "###showing compiled version of packet"
		datapacket.show2()
		mystream.send(datapacket)##ipLayer
		#print "this is what we just sent"
		#datapacket.show()

	else:
		send(packet)
	#print "seq sent is: "+str(mystream.ack)
	print "Following Message Sent"
	packet.show2()
	#seq = response.ack
	#ack=
	#print "new seq valu: " + str(seq)
	#updateField("Transport","seq", seq)
	
	#TODO, check for "autoupdates" on each layer, and show them on UI next to the field they created a value for
	lar = packet
	while lar:
		autofound = 0
		layername = ""
		for i in inspect.getmembers(lar):
			if i[0] == 'autoupdates':
				autofound = 1
			if i[0] == 'name':
				layername = i[1]
		
		if autofound == 0:
			print "\n\n"+repr(layername)+" has no auto-updates.\n\n"
		else:
			print "\n\n"+repr(layername)+" auto-updates: "+repr(lar.autoupdates)+"\n\n"
			for field in lar.autoupdates:
				print "auto-update:"+repr(field)+"with "+repr(lar.autoupdates[field])+"\n"
		lar = lar.payload
	#getProtoLayerSize()
	#proto_length = len(datalayer)
	#print "packet_length: "+ repr(proto_length)		
	#rebuildIPlayer()


	
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
	send(ip/ACK)
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
firstField = 2
formFields = []
formdescs = []
layers = []
layerindex = []
fieldArray = []
hidden = True
root = Tk()
root.title("Traffic Based Model Generator")

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

page4 = ttk.Frame(nb)
nb.add(page4, text='Create Dissector')

app = Application(root)
root.mainloop()

