import sys,os
import json,random,string
import hashlib,base64,subprocess
from Tkinter import *
from ttk import * # overrides the styles of some (but not all) Tkinter classes
import ttk, tkMessageBox
from tkFileDialog import askopenfilename
import random
import datetime

# functions for dealing with bubbling up errors (see helpers.lib.php for parallels)
loggederrors = []
def LogError(message,obj=None):
	global loggederrors
	objstr = ("" if obj is None else ": "+json.dumps(obj));
	fullstr = str(message)+objstr
	loggederrors.append(fullstr)
	sys.stderr.write(fullstr+"\n")
def HaveErrors():
	global loggederrors
	return len(loggederrors) > 0
def GetErrors():
	global loggederrors
	errstr = "\n\n".join(loggederrors)
	loggederrors = []
	return errstr

def ShellSafe(args):
	safestr = ""
	for arg in args:
		if safestr == "":
			safestr += arg
		else:
			safearg = arg
			safearg = safearg.replace("\\","\\\\")
			safearg = arg.replace('"','\\"')
			safestr += " \""+safearg+"\""
	return safestr
def OSOpen(filename):
	subprocess.Popen(['xdg-open',filename])
def TextEditorOpen(filename):
	subprocess.Popen(['gedit',filename])

def AlertPop(title,msg):
	print " "
	print "/--" + "-"*len(title) + "--\\"
	print "|  " + title + "  |"
	print "|" + "-"*79
	print msg
	print " "
	tkMessageBox.showinfo(title,msg)
def HelperBTN(par, row, col, title, msg):
	# nb = ttk.Button(par,text='?',pady=0,command=lambda t=title,h=msg: AlertPop(t,h))
	nb = ttk.Button(par,text='?',width=2,command=lambda t=title,h=msg: AlertPop(t,h))
	nb.grid(row=row,column=col)
	
def KWARGSValidate(sent,define):
	problems = ""
	for key in define:
		obj = define[key]
		if type(obj).__name__ == "str":
			obj = {"desc":obj}
		obj = ApplyDefaults(obj,{"desc":"--no description--","req":True,"nonempty":False})
		
		if obj["req"] and key not in sent:
			problems += "Missing argument: "+key+"\n   "+obj["desc"]+"\n\n"
		if key not in sent:
			next
			
		if obj["nonempty"] and str(sent[key]) == "":
			problems += "Field expected to be non-empty: "+key+"\n    "+obj["desc"]+"\n\n";
		
	return problems

def ApplyDefaults(obj,defaults):
	for key in defaults:
		if key not in obj:
			obj[key] = defaults[key]
	return obj


def GUILauncher(frameclass,title,*argv):
	root = Tk()
	root.title(title)
	app = Frame(root)
	app.grid()
	mgui = frameclass(app,*argv)
	mgui.grid()
	root.mainloop()

def ATK_InitRowCounter(value=1):
	newvar = IntVar()
	newvar.set(value)
	return newvar
def ATK_IncrementRowCounter(rowVar,increment=1):
	rowVar.set(rowVar.get()+increment)
def ATK_Tabbed(parent,rowVar,col,**kwargs):
	newtabs = Notebook(parent)
	ApplyDefaults(kwargs,{"row":rowVar.get(),"column":col,"columnspan":5,"rowspan":5,"sticky":"NSEW"})
	newtabs.grid(**kwargs)
	ATK_IncrementRowCounter(rowVar,kwargs["rowspan"])
	return newtabs
def ATK_TabbedAdd(parent,label):
	newtab = Frame(parent)
	parent.add(newtab, text=label)
	return newtab
def ATK_TextField(parent,rowVar,col,label,value,helper=""):
	if helper <> "":
		HelperBTN(parent,rowVar.get(),col,label,helper)
	newlabel = Label(parent, text=label+":")
	newlabel.grid(row=rowVar.get(),column=col+1,sticky="E")
	newtext = Entry(parent)
	newtext.grid(row=rowVar.get(),column=col+2,sticky="EW")
	newtext.insert(0,str(value))
	ATK_IncrementRowCounter(rowVar,1)
	return newtext
def ATK_TextArea(parent,rowVar,col,label="",value="",width=30,height=8,helper=""):
	if helper <> "" or label <> "":
		ATK_Label(parent,rowVar,col,label,helper)
	newtxt = Text(parent,width=width,height=height,wrap=NONE)
	newtxt.grid(row=rowVar.get(),column=0,columnspan=4,sticky="EW")
	newtxt.insert(END,str(value))
	newtxt.str = lambda: newtxt.get(1.0,END)
	ATK_ScrollAttach(parent,rowVar,col,newtxt)
	ATK_IncrementRowCounter(rowVar,2)
	return newtxt
def ATK_ReadOnlyField(parent,rowVar,col,label,value,helper=""):
	newfield = ATK_TextField(parent,rowVar,col,label,value,helper)
	newfield.config(state="readonly")
	return newfield
def ATK_Label(parent,rowVar,col,label,helper=""):
	if helper <> "":
		HelperBTN(parent,rowVar.get(),col,label,helper)
	newlabel = Label(parent,text=label+":")
	newlabel.grid(row=rowVar.get(),column=col+1,columnspan=3,sticky="W")
	ATK_IncrementRowCounter(rowVar,1)
	return newlabel
def ATK_LabelField(parent,rowVar,col,label,value,helper=""):
	if helper <> "":
		HelperBTN(parent,rowVar.get(),col,label,helper)
	newlabel = Label(parent,text=label+":")
	newlabel.grid(row=rowVar.get(),column=col+1,sticky="E")
	newdisp = Label(parent,text=value)
	newdisp.grid(row=rowVar.get(),column=col+2,sticky="EW")
	ATK_IncrementRowCounter(rowVar,1)
	return newdisp
def ATK_ButtonSingle(parent,rowVar,col,label,btnwords,callback,helper=""):
	if helper <> "":
		HelperBTN(parent,rowVar.get(),col,label,helper)
	newlabel = Label(parent,text=label+":")
	newlabel.grid(row=rowVar.get(),column=col+1,sticky="E")
	newbtn = Button(parent,text=btnwords,command=callback)
	newbtn.grid(row=rowVar.get(),column=col+2,sticky="EW")
	ATK_IncrementRowCounter(rowVar,1)
	return newbtn
def ATK_ButtonAlone(parent,rowVar,col,btnwords,callback,helper=""):
	if helper <> "":
		HelperBTN(parent,rowVar.get(),col,label,helper)
	newbtn = Button(parent,text=btnwords,command=callback)
	newbtn.grid(row=rowVar.get(),column=col,columnspan=4,sticky="EW")
	ATK_IncrementRowCounter(rowVar,1)
	return newbtn
def ATK_FileSelect(parent,rowVar,col,label,askargs,helper=""):
	if helper <> "":
		HelperBTN(parent,rowVar.get(),col,label,helper)
	newlabel = Label(parent, text=label+":")
	newlabel.grid(row=rowVar.get(),column=col+1,sticky="E")
	newstr = StringVar()
	newtext = Entry(parent, textvariable=newstr)
	newtext.grid(row=rowVar.get(),column=col+2,sticky="EW")
	def filediaglaunch():
		newfilename = StringVar()
		newfilename.set(askopenfilename(**askargs))
		if newfilename.get() <> "":
			newstr.set(newfilename.get())
	newbtn = Button(parent, text="Select", command=filediaglaunch)
	newbtn.grid(row=rowVar.get(),column=col+3,sticky="W")
	ATK_IncrementRowCounter(rowVar,1)
	return newstr
def ATK_ScrollAttach(parent,rowVar,col,target):
	scrollX = Scrollbar(parent,command=target.xview,orient=HORIZONTAL)
	scrollY = Scrollbar(parent,command=target.yview,orient=VERTICAL)
	target.config(xscrollcommand=scrollX.set)
	target.config(yscrollcommand=scrollY.set)
	scrollX.grid(row=rowVar.get()+1,column=col,sticky="EWN",columnspan=4)
	scrollY.grid(row=rowVar.get(),column=col+4,sticky="NSw",rowspan=1)
	return True
def ATK_ScrollFrame(parent,rowVar,col,widthpx,heightpx):
	newcanvas = Canvas(parent,width=widthpx,height=heightpx,bg='red')
	newcanvas.grid(row=rowVar.get(),column=col,columnspan=4)
	ATK_ScrollAttach(parent,rowVar,col,newcanvas)
	
	#TODO: this doesn't actually work... problem is probably here abouts
	# newframe = Frame(width=widthpx)
	newframe = Frame(newcanvas,width=widthpx)
	newcanvas.create_window(0,0,anchor="nw",window=newframe)
	# newframe.grid(row=0,column=0)
	# newcanvas.config(scrollregion=newcanvas.bbox("all"))
	
	ATK_IncrementRowCounter(rowVar,2)
	return newframe
def ATK_SubFrame(parent,rowVar,col,label="",helper=""):
	if helper <> "" or label <> "":
		if helper <> "":
			HelperBTN(parent,rowVar.get(),0,label,helper)
		newlabel = Label(parent,text=label)
		newlabel.grid(row=rowVar.get(),column=col+1,sticky="EW")
		newdash = Frame(parent,borderwidth=3,relief=GROOVE)
		newdash.grid(row=rowVar.get(),column=col+2,columnspan=3,sticky="EW")
		subdash = Label(newdash,text=" ",font=("Courier",1),width=200)
		subdash.grid(row=0,column=0,sticky="EW")
		ATK_IncrementRowCounter(rowVar,1)
		sidedash = Frame(parent,borderwidth=3,relief=GROOVE)
		sidedash.grid(row=rowVar.get(),column=col,columnspan=1,sticky="NS")
		sidesubdash = Label(sidedash,text=" ",font=("Courier",1),width=1)
		sidesubdash.grid(row=rowVar.get(),column=col,sticky="NS")
		
	newframe = Frame(parent) #,borderwidth=3,relief=GROOVE)
	newframe.grid(row=rowVar.get(),column=col+1,columnspan=3,sticky="EW")	
	ATK_IncrementRowCounter(rowVar,1)
	return newframe
def ATK_BR(parent,rowVar,col):
	newlabel = Label(parent,text="  ")
	newlabel.grid(row=rowVar.get(),column=col,columnspan=5)
	ATK_IncrementRowCounter(rowVar,1)
	return newlabel
def ATK_HR(parent,rowVar,col):
	sublabel = Label(parent,text="",font=("Courier",1),width=200)
	sublabel.grid(row=rowVar.get(),column=0,columnspan=5,sticky="EW")
	ATK_IncrementRowCounter(rowVar,1)
	newdash = Frame(parent,borderwidth=3,relief=GROOVE)
	newdash.grid(row=rowVar.get(),column=col,columnspan=5,sticky="EW")
	subdash = Label(newdash,text="",font=("Courier",1),width=200)
	subdash.grid(row=0,column=0,sticky="EW")
	ATK_IncrementRowCounter(rowVar,1)
	sublabel = Label(parent,text="",font=("Courier",1),width=200)
	sublabel.grid(row=rowVar.get(),column=0,columnspan=5,sticky="EW")
	ATK_IncrementRowCounter(rowVar,1)
	return newdash

def ATK_ObjList(parent,rowVar,col,lineconfig,callback):
	# lineconfig format example:
	# cols = []
	# cols.append({"field":"ident","label":"ID","align":"right"})
	# cols.append({"field":"label","label":"Name","align":"left","width":15})
	# cols.append({"field":"data","label":"Data","align":"left","width":20})
	
	header = ""
	for field in lineconfig:
		if "label" not in field:
			field["label"] = field["field"]
		if "width" not in field:
			field["width"] = len(field["label"])
		if field["width"] < len(field["label"]):
			field["width"] = len(field["label"])
		if "align" not in field:
			field["align"] = "left"
		if "clipalign" not in field:
			field["clipalign"] = "left"
		
		if "right" == field["align"]:
			field["label"] = " "*(field["width"]-len(field["label"]))+field["label"]

		header += field["label"] + " "*(field["width"]-len(field["label"])) + "  "
	header = header[:len(header)-2] #remove trailing "  "
	widthchar = len(header)
	
	newlist = Listbox(parent,width=widthchar,height=max(5,int(widthchar/4)))
	newlist.config(font="Courier")
	newlist.grid(row=rowVar.get(),column=col,columnspan=4)
	newlist.insert(END,header)
	
	newlist.lineconfig = lineconfig
	newlist.objects = []
	def selCaller(num):
		items = newlist.curselection()
		
		if len(items) < 1:
			return
		if items[0] == 0:
			return
			
		try:
			callback(newlist.objects[int(items[0])-1])
		except ValueError: pass
	newlist.bind("<Double-Button-1>",selCaller)
	
	ATK_ScrollAttach(parent,rowVar,col,newlist)
	
	newlist.itemconfig(0,background="#dddddd",selectbackground="#dddddd")
	
	ATK_IncrementRowCounter(rowVar,2)
	return newlist
def ATK_ObjList_AddItem(objlist,obj):
	
	mStr = ""
	
	for col in objlist.lineconfig:
		val = ""
		if col["field"] in obj:
			val = ATK_str(obj[col["field"]])
		
		width = len(val)
		if width > col["width"]:
			over = width - col["width"]
			if col["width"] > 5:
				if col["clipalign"] == "right":
					mStr += "..." + val[(over+3):]
				elif col["clipalign"] == "wings":
					mStr += val[:int(col["width"]/2)-2]+"..."+val[int(width-col["width"]/2)+1:]
				else: #left
					mStr += val[:(col["width"]-3)] + "..."
			else:
				if col["clipalign"] == "right":
					mStr += "~" + val[(over+1):]
				else: #left
					mStr += val[:(col["width"]-1)] + "~"
		else:
			pad = " "*(col["width"]-width)
			padL = ""
			padR = ""
			if "left" == col["align"]:
				padR = pad
			if "right" == col["align"]:
				padL = pad
			if "center" == col["align"]:
				padL = pad[:int(len(pad)/2)]
				padR = pad[len(padL):]
			mStr += padL + val + padR
		
		mStr += "  "
	
	mStr = mStr[:len(mStr)-2] #remove trailing "  "
	
	objlist.insert(END,mStr)
	objlist.objects.append(obj)
	
	if "_color" in obj:
		if "_scolor" not in obj:
			obj["_scolor"] = ColorShift(obj["_color"],-1)
		objlist.itemconfig(len(objlist.objects),background=obj["_color"],selectbackground=obj["_scolor"])
def ATK_str(var):
	nvar = ""
	for c in str(var):
		if c in string.printable:
			nvar += c
		else:
			repc = repr(c)
			nvar += repc[1:len(repc)-1]
	return nvar

def ColorShift(hexcolor,shift):
	
	d2h = [0,1,2,3,4,5,6,7,8,9,'A','B','C','D','E','F']
	h2d = {'a':10,'A':10,'b':11,'B':11,'c':12,'C':12,'d':13,'D':13,'e':14,'E':14,'f':15,'F':15}
	for i in range(0,10):
		h2d[str(i)] = i
	
	newcolor = ""
	for c in hexcolor:
		if c in h2d:
			v = h2d[c]
			nv = max(0,min(15,v+shift))
			c = str(d2h[nv])			
		newcolor += c
	
	return newcolor
	

# returns an image file as a URI ready (base 64) string
def icon_uri(filename,size=32):

	tmpfilename = icon_resize(filename,size)
	with open(tmpfilename,'r') as f:
		pngdata = f.read()

	return "data:image/png;base64, "+base64.b64encode(pngdata)

# returns a filename (in /tmp) for where the resized icon file was put
def icon_resize(filename,size):

	tmpfilename = os.path.join("/tmp","icon_"+str(size)+"_"+hashlib.md5(str(filename)).hexdigest()+'.png')

	if os.path.isfile(tmpfilename):
		return tmpfilename

	fsafe = '"'+filename.replace('\\','\\\\').replace('"','\\"')+'"'
	if not os.path.isfile(filename):
		fsafe = "-size 120x120 pattern:checkerboard -colorize 0,50,50"
	sizer = str(int(size))+'x'+str(int(size))
	os.system('convert '+fsafe+' -resize '+sizer+' '+tmpfilename)

	return tmpfilename

# returns the IP addresses associated with this system
def getmyIPaddresses():
	
	results = {}
	
	infs = subprocess.check_output(["ip","-o","address"]).split("\n")
	for inf in infs:
		if inf == "":
			continue
		try:
			pieces = splitEasy(inf," ")
			interface = pieces[1]
			itype = pieces[2]
			slash = pieces[3]
			address,bitsize = slash.split("/")
			results[interface+"."+itype] = {"interface":interface,"type":itype,"address":address,"subnetbits":bitsize,'slash':slash}
		except:
			LogError("getmyIPaddresses unable to process line",inf)
	
	return results

# splits a string, but removes empty items
def splitEasy(line,delim):
	raw = line.split(delim)
	pieces = []
	for i in raw:
		if i != "":
			pieces.append(i)
	return pieces

_saferand_archive = {}
def SafeRand():
	global _saferand_archive
	
	while True:
		newrand = random.randint(100000,999999)
		if not (newrand in _saferand_archive):
			break

	return newrand

def nowstr():
	dt = datetime.datetime.now()
	return dt.strftime("%Y-%m-%d-%H-%M-%S")

if __name__ == "__main__":
	print ("*  *"*20)+"helpers.py is not meant to be run, but instead: from lib.helpers import *\n"+(" ** "*20)
	# but, you can put some temporary testing code here to quickly test new helpers
	# print ColorShift("#ff9944",1) + " should be #FFAA55\n\n"
