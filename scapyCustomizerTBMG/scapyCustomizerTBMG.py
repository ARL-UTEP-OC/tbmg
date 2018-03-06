from collections import OrderedDict
import re

#pattern:
# a = scapyCustomizerTBMG(filename)       #open the file for editing
# valueobject = a.getedits(somefieldname) #get a field's customizations, can also send "_GENERAL_"
# someGUIstarter(valueobject)             #send it somewhere
# newvalueobject = someGUIender()         #get it back from somewhere
# a.update(somefieldname,newvalueobject)  #update the field (or "_GENERAL_")
# a.rewrite()                             #overwrite the original file

def extag(line):
	match = re.match("[# \.\*]+(?P<tag>.*?)[\.\*]+.*",line)
	return match.groupdict()['tag']

def RESTlogic(key,nfbs,mfbs):
	if key == "REST":
		return "packet_bytes[("+nfbs+"-"+mfbs+"):]+payload_bytes"
	elif key == "PACKET":
		return "packet_bytes"
	elif key == "PAYLOAD":
		return "payload_bytes"
	elif key == "TOTAL":
		return "packet_bytes+payload_bytes"
	return "(self."+key+" if '"+key+"' not in synthfields else synthfields['"+key+"'])"

def LENlogic(key,nfbs,mfbs):
	return "len("+RESTlogic(key,nfbs,mfbs)+")"

def SEQlogic(key,nfbs,mfbs):
	if str(int(key)) == str(key):
		return key
	return LENlogic(key,nfbs,mfbs)

def RePacket(fbs,mfbs,nfbs,var,endian):
	return """packet_bytes = packet_bytes[0:("""+fbs+"-"+mfbs+""")]+"""+PackLogic(nfbs,fbs,var,endian)+"""+packet_bytes[("""+nfbs+"-"+mfbs+"""):]"""

def PackLogic(nfbs,fbs,var,endian):
	return _packer(nfbs,fbs,var,"pack","str",endian)
def UnpackLogic(nfbs,fbs,var,endian):
	return _packer(nfbs,fbs,var,"unpack","",endian)+"[0]"

def _packer(nfbs,fbs,var,pcom,scom,endian):
	if str(int(nfbs)) != str(nfbs) or str(int(fbs)) != str(fbs):
		print "WARNING: dynamic pack length, using string array"
		return "struct."+pcom+"('"+endian+"'+str("+nfbs+"-"+fbs+")+'s',"+scom+"("+var+"))"
	diff = int(nfbs)-int(fbs)
	if diff == 1:
		return "struct."+pcom+"('"+endian+"B',"+var+")"
	if diff == 2:
		return "struct."+pcom+"('"+endian+"H',"+var+")"
	if diff == 4:
		return "struct."+pcom+"('"+endian+"L',"+var+")"
	if diff == 8:
		return "struct."+pcom+"('"+endian+"Q',"+var+")"
	print "WARNING: to pack number into "+str(diff)+" bytes, using string array"
	return "struct."+pcom+"('"+endian+""+str(diff)+"s',"+scom+"("+var+"))"


def StoreSynth(field,fbs,mfbs,nfbs):
	return """synthfields['"""+field+"""'] = packet_bytes[("""+fbs+"-"+mfbs+"""):("""+nfbs+"-"+mfbs+""")]"""

def codeServe(linesarr,indent):
	striparr = []
	for line in linesarr:
		striparr.append(line[indent:])
	return "\n".join(striparr)

def codeStore(linesstr,indent):
	
	linesarr = linesstr.split("\n")
	while len(linesarr) > 0 and linesarr[-1] == "":
		linesarr.pop()
	
	keeparr = []
	for line in linesarr:
		keeparr.append((" "*indent)+line)
		
	return keeparr

class scapyCustomizerTBMG(object):
	
	def __init__(self, filename):
		
		with open(filename) as f:
			fileraw = f.read()
		
		lines = fileraw.split("\n")
		
		fields = OrderedDict()
		fieldprocorder = []
		
		tagged = OrderedDict()
		otherlines = OrderedDict()
		classname = ""
		
		states = ['post','mid','start']
		for s in states:
			otherlines[s] = []
		state = states.pop()
		
		tagstack = []
		tag = ''
		
		for line in lines:
			
			if re.match("# \.\..*?\*\*.*",line): #leaving tag
				if len(tagstack) == 0:
					tag = ""
					state = states.pop()
				else:
					tag = tagstack.pop()
				continue
				
			if re.match("# \*\*.*?\.\..*",line): #entering tag
				if tag != "":
					tagstack.append(tag)
				tag = extag(line)
				ftag = ".".join(tagstack + [tag])
				tagged[ftag] = []
				if "TBMG._FIELDS_." in ftag and tag != "code":
					fieldprocorder.append(tag)
				continue

			if "class " in line:
				if "TBMG_PRE" not in tagged:
					state = states.pop()
					#let it store the line like usual
				if state == 'mid':
					classname = line.split('(',1)[0].split(' ')[-1]
			
			if tag == "":
				otherlines[state].append(line)
				
				match = re.match(".*?\(\"(?P<field>.*?_(?P<pos>\d+))\",.*",line)
				if match:
					fields[match.groupdict()['field']] = match.groupdict()['pos']
				
				continue
			else:
				ftag = ".".join(tagstack + [tag])
				tagged[ftag].append(line)
				continue

		for t in ["TBMG_PRE","TBMG","TBMG._FIELDS_"]:
			if t in tagged:
				del tagged[t]
		for t in ["TBMG_PRE._GENERAL_","TBMG._GENERAL_","TBMG._GENERAL_FIRST_"]:
			if t not in tagged:
				tagged[t] = []
		for f in fields:
			tf = "TBMG._FIELDS_."+f
			if tf not in tagged:
				tagged[tf] = ["# NONE"]
			
			if tagged[tf][0] == "# CUSTOM":
				tfc = tf+".code"
				if tfc not in tagged or len(tagged[tfc]) == 0:
					tagged[tf] = ["# NONE"]

			tagged[tf] = tagged[tf][0][2:] #just keep the string fragment, to regen later
		
		nextfields = OrderedDict()
		last = None
		for f in fields:
			if last is None:
				last = f
				continue
			nextfields[last] = fields[f]
			last = f
		nextfields[last] = 0
		
		for f in fields:
			if f not in fieldprocorder:
				fieldprocorder.append(f)

		self.filename = filename
		self.classname = classname
		self.fieldbytes = fields
		self.fieldorder = fieldprocorder
		self.minfieldbyte = min(fields.values())
		self.nextfieldbytes = nextfields
		self.tagged = tagged
		self.otherlines = otherlines

	def reform(self):
		
		lines = []
		
		for line in self.otherlines['start']:
			lines.append(line)
		
		lines.append("# **TBMG_PRE... WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG")
		lines.append("""
import struct,time,inspect,math,os
from collections import OrderedDict
TBMG_synthfields_"""+self.classname+""" = OrderedDict()
		""")
		lines.append("# ***_GENERAL_...")
		for line in self.tagged['TBMG_PRE._GENERAL_']:
			lines.append(line)
		lines.append("# ..._GENERAL_***")
		lines.append("# ..TBMG_PRE*** WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG")
		
		for line in self.otherlines['mid']:
			lines.append(line)
		
		lines.append("# **TBMG... WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG")
		lines.append("""
    def post_build(self, packet_bytes, payload_bytes):
        global TBMG_synthfields_"""+self.classname+"""

        actualsend = os.path.isfile(os.path.join(os.path.expanduser("~"),".TBMG_ActualSend"))
        lastsynthfields = TBMG_synthfields_"""+self.classname+"""
        synthfields = OrderedDict()
        synthfields["__class"] = '"""+self.classname+"""'
		""")
		
		lines.append("# **_GENERAL_FIRST_...""")
		for line in self.tagged["TBMG._GENERAL_FIRST_"]:
			lines.append(line)
		lines.append("# .._GENERAL_FIRST_***")

		lines.append("")
		lines.append("# **_FIELDS_...")

		mfbs = str(self.minfieldbyte) #mininum field byte [as] string
		for field in self.fieldorder:
			tfc = "TBMG._FIELDS_."+field
			special = self.tagged[tfc]
			fbs = str(self.fieldbytes[field]) #field byte [as] string
			nfbs = str(self.nextfieldbytes[field]) #next field byte [as] string
			if nfbs == "0": #last field, so goes to end of packet
				nfbs = "(len(packet_bytes)+"+mfbs+")"
			lines.append("")
			lines.append("# ***"+field+"...")
			lines.append("# "+special)
			
			if special == "NONE":
				lines.append("""
        """+StoreSynth(field,fbs,mfbs,nfbs)+"""
				""")

			elif special == "CUSTOM":
				lines.append("""
        field_start = """+fbs+"-"+mfbs+"""
        field_end = """+nfbs+"-"+mfbs+"""
        field_bytes = packet_bytes[field_start:field_end]
				""")
				lines.append("# ****code...")
				for line in self.tagged[tfc+".code"]:
					lines.append(line)
				lines.append("# ....code***")
				lines.append("""
        synthfields['"""+field+"""'] = field_bytes
        packet_bytes = packet_bytes[0:field_start]+field_bytes+packet_bytes[field_end:]
				""")

			elif special[0:4] == "LEN ":
				ignore,key,endian = special.split(" ")
				keylen = LENlogic(key,nfbs,mfbs)
				lines.append("""
        if self."""+field+""" is None:
            length = """+keylen+"""
            """+RePacket(fbs,mfbs,nfbs,"length",endian)+"""
        """+StoreSynth(field,fbs,mfbs,nfbs)+"""
				""")
			
			elif special[0:7] == "CHKSUM ":
				ignore,alg,key,endian = special.split(" ")
				keydata = RESTlogic(key,nfbs,mfbs)
				algfunc = alg
				if alg == "INET":
					algfunc = "checksum"
				lines.append("""
        if self."""+field+""" is None:
            chk = """+algfunc+"""("""+keydata+""")
            """+RePacket(fbs,mfbs,nfbs,"chk",endian)+"""
        """+StoreSynth(field,fbs,mfbs,nfbs)+"""
				""")
				
			elif special[0:4] == "SEQ ":
				ignore,numer,denum,endian = special.split(" ")
				numerlen = SEQlogic(numer,nfbs,mfbs)
				denumlen = SEQlogic(denum,nfbs,mfbs)
				lines.append("""
        if self."""+field+""" is None:
            seq = int("""+UnpackLogic(nfbs,fbs,"packet_bytes[("""+fbs+"-"+mfbs+"):("+nfbs+"-"+mfbs+")]",endian)+""")
            if '"""+field+"""' in lastsynthfields:
                seq = int("""+UnpackLogic(nfbs,fbs,"lastsynthfields['"+field+"']",endian)+""")
            if actualsend:
				seq += int(math.ceil(("""+numerlen+""")/("""+denumlen+""")))
            """+RePacket(fbs,mfbs,nfbs,"seq",endian)+"""
        """+StoreSynth(field,fbs,mfbs,nfbs)+"""
				""")
				
			elif special[0:10] == "TIMESTAMP ":
				ignore,offset,endian = special.split(" ")
				lines.append("""
        if self."""+field+""" is None:
            ts = time.time() + """+offset+"""
            """+RePacket(fbs,mfbs,nfbs,"ts",endian)+"""
        """+StoreSynth(field,fbs,mfbs,nfbs)+"""
				""")
						
			lines.append("# ..."+field+"***")
		
		lines.append("")
		lines.append("# .._FIELDS_***")
		lines.append("")

		lines.append("# **_GENERAL_...""")
		for line in self.tagged["TBMG._GENERAL_"]:
			lines.append(line)
		lines.append("# .._GENERAL_***")

		lines.append("""
        print ""
        print "is actual send: "+("YES" if actualsend else "NO")
        print "lastsynthfields count: "+str(len(lastsynthfields))
        for f in lastsynthfields:
            print "      "+f.rjust(20)+" -- "+repr(lastsynthfields[f])
        print "###[ """+self.classname+""" ]###"
        for f in synthfields:
            print "      "+f.rjust(20)+" = "+repr(synthfields[f])

        TBMG_synthfields_"""+self.classname+""" = synthfields
        return packet_bytes+payload_bytes
		""")
		
		lines.append("""
    def cloner(self,old):
        for f in old.fields_desc:
            val = getattr(old,f.name)
            print "transferring value "+str(f.name)+": "+str(val)
            setattr(self,f.name,val)

		""")
		
		lines.append("# ..TBMG*** WARNING: DO NOT MANUALLY EDIT CODE INSIDE TAG")

		for line in self.otherlines['post']:
			lines.append(line)
		
		return "\n".join(lines)
		
	def rewrite(self):
		
		newstr = self.reform()
		
		with open(self.filename,'w') as f:
			f.write(newstr)
		
	def hasedits(self,fieldname):
		
		if fieldname == '_GENERAL_':
			for f in ['TBMG._GENERAL_','TBMG._GENERAL_FIRST_','TBMG_PRE._GENERAL_']:
				if len(self.tagged[f]) > 0:
					return True
			return False
		
		tfc = "TBMG._FIELDS_."+fieldname
		if tfc not in self.tagged:
			return False
			
		if self.tagged[tfc] == "NONE":
			return False
			
		return True
		
		
	def getedits(self,fieldname):
		
		if fieldname == "_GENERAL_":
			return {"LOGIC":"CUSTOM","PRE":codeServe(self.tagged["TBMG_PRE._GENERAL_"],0),"FIR":codeServe(self.tagged["TBMG._GENERAL_FIRST_"],8),"GEN":codeServe(self.tagged["TBMG._GENERAL_"],8)}
		
		tfc = "TBMG._FIELDS_."+fieldname	
		if tfc not in self.tagged:
			return "ERROR: unknown field "+fieldname
		
		edits = {"LOGIC":self.tagged[tfc]}
		if self.tagged[tfc] == "CUSTOM":
			edits["CODE"] = codeServe(self.tagged[tfc+'.code'],8)

		last = "RUN FIRST"
		for f in self.fieldorder:
			if f == fieldname:
				break
			last = f
		edits["AFTER"] = last

		return edits
		
	def saveEdits(self,fieldname,edits):
		
		if fieldname == '_GENERAL_':
			self.tagged["TBMG_PRE._GENERAL_"] = codeStore(edits["PRE"],0)
			self.tagged["TBMG._GENERAL_FIRST_"] = codeStore(edits["FIR"],8)
			self.tagged["TBMG._GENERAL_"] = codeStore(edits["GEN"],8)
		else:
			tfc = "TBMG._FIELDS_."+fieldname
			if tfc not in self.tagged:
				print "ERROR: unknown field "+fieldname
				return False
			self.tagged[tfc] = edits['LOGIC']
			if edits['LOGIC'] == "CUSTOM":
				self.tagged[tfc+'.code'] = codeStore(edits["CODE"],8)
				
		if "AFTER" in edits:
			neworder = []
			if edits['AFTER'] == "RUN FIRST":
				neworder.append(fieldname)
			while len(self.fieldorder) > 0:
				f = self.fieldorder.pop(False)
				if f == fieldname:
					continue
				neworder.append(f)
				if f == edits['AFTER']:
					neworder.append(fieldname)
			self.fieldorder = neworder

		self.rewrite()
		return True
		
	def getoptions(self,field):
		
		opts = OrderedDict()
		edits = self.getedits(field)
		
		codehelp = """
variables available:
  packet_bytes  - the whole packet (as as string of bytes), at this layer
  payload_bytes - the payload (as a string of bytes), which is most likely empty for TBMG usage
  synthfields   - OrderedDict() of the fields after modification, or any other information between packet calculations
  lastsynthfields - the synthfields from last time the packet was calculated
  actualsend    - True when called by send() via TBMG, False when called by show2() (or from send() outside of TBMG)
  
NOTICE: Python indentation is 4 spaces for these code snippets
		""";
		
		selhelp = """
dropdown options may include:
  numbers - constants
  fields  - to get hte length of the field
  REST    - the length of all fields after this one, and the payload (at the time this field is processed)
  TOTAL   - the length of the packet and payload (at the time the field is processed)
  PACKET  - the length of the packet (at the time the field is processed)
  PAYLOAD - the length of the payload, which should be 0 for most TBMG usages
"""

		chkhelp = """
dropdown options may include:
  INET    - typical checksum (provided by scapy) used in internet protocols
"""

		EndianHelp = """
Endian encoding for how to pack the bytes.
Sent directly to struct.pack() calls, for example struct.pack("!H",bytes) will pack 2 bytes in internet standard format
see http://docs.python.org/2/library/struct.html#byte-order-size-and-alignment for full details

  !   - network (big-endian) standard
  <   - little-endian
  >   - big-endian
"""
		Endians = ['!','<','>']

		customhelp = """
Allows writing any code.
If editing a field, variables will be provided to assist with processing the field.
Editing the main protocol class will provide access	to imports, and to code run after all fields.
For example, if you wanted to make a 1 byte field give itself a random value each time, you would...
 - edit the main class, and use the imports section to "import random"
 - edit the field itself, and use "field_bytes = struct.pack("!B",random.randint(0,255))"
"""

		mustNone = """
IMPORTANT: the field value must be set to "None" in order for this logic to run.
"""
		mustActual = """
IMPORTANT: this only updates during a recognized send()
"""

		if field == "_GENERAL_":
			opts['CUSTOM'] = OrderedDict()
			opts['CUSTOM']['help'] = customhelp
			opts['CUSTOM']['PRE'] = {'type':'textarea','title':'imports section','help':"""
Section of code before the class declaration.
Especially useful for imports.
""",'default':''}
			opts['CUSTOM']['FIR'] = {'type':'textarea','title':'post_build first','help':"""
Runs near the beginning of post_build(), before any fields (but after lastsynthfields is prepped)
Useful for setting up local variables used by later field logic.
""",'default':''}
			opts['CUSTOM']['GEN'] = {'type':'textarea','title':'post_build last','help':"""
Runs near the end of post_build(), after all field modifications.
Useful for complex operations, such as...
  - redoing a length field if also dynamically modifying a variable length field.
  - storing values into synthfields for use in later calculations
  - sending debug info to the background terminal
  - modifying what is reported back to the GUI via synthfields
"""+codehelp+"""
""",'default':''}
			return opts
		
		RESTfields = []
		SEQfields  = []
		AFTERfields = []
		RESTfields.append('REST')
		RESTfields.append('TOTAL')
		RESTfields.append('PACKET')
		RESTfields.append('PAYLOAD')
		SEQfields.append('1')
		SEQfields.append('2')
		SEQfields.append('4')
		SEQfields.append('8')
		SEQfields.append('16')
		SEQfields.append('32')
		SEQfields.append('64')
		SEQfields.append('128')
		SEQfields.append('256')
		SEQfields.append('512')
		SEQfields.append('1024')
		SEQfields.append('REST')
		SEQfields.append('TOTAL')
		SEQfields.append('PACKET')
		SEQfields.append('PAYLOAD')
		AFTERfields.append("RUN FIRST")
		for i in self.fieldbytes:
			if i == field:
				continue
			RESTfields.append(i)
			SEQfields.append(i)
		
		for i in self.fieldorder:
			if i == field:
				continue
			AFTERfields.append(i)
		
		CHKalgs = []
		CHKalgs.append('INET')
		
		opts['_AFTER'] = {'type':'select','title':'Run after','source':AFTERfields,'help':"""
Set which field this will be processed after.
Useful for moving LEN fields after processing a variable length field.
Useful for moving CHKSUM fields after processing all fields that come afterwards
""",'default':edits['AFTER']}
		
		opts['NONE'] = OrderedDict()
		opts['NONE']['help'] = """
The "NONE" option means no special processing will be done.
The value will still be reported back via "synthfields"
"""
		
		opts['CUSTOM'] = OrderedDict()
		opts['CUSTOM']['help'] = customhelp
		opts['CUSTOM']['CODE'] = {'type':"textarea",'title':'Code','help':"""
Primarily, modify only this one variable:
  field_bytes   - the string of bytes for this field
Some other handy variables:
  field_start   - the byte position this field starts at
  field_end     - the byte position this field [currently] ends at
"""+codehelp+"""
""","default":""}
		
		opts['LEN'] = OrderedDict()
		opts['LEN']['help'] = """
Sets the field to the byte length of some other field.
WARNING: if you modify the target field AFTER this length, you will need to use the class's general code to manually fix the length.
"""+mustNone+"""
"""
		opts['LEN']['arg1'] = {'type':'select','title':'Length of','source':RESTfields,'help':"""
Which field, or fields, to take the length of
""",'default':'REST'}
		opts['LEN']['arg2'] = {'type':'select','title':'Endian','source':Endians,'help':EndianHelp,'default':'!'}
		
		opts['SEQ'] = OrderedDict()
		opts['SEQ']['help'] = """
Sets the field to an increment higher than the previous value.
It increments by the ceiling(Numerator/Denominator)
So, if you want to increment by just 1, then ceiling(1/1) = 1, so set both to 1
Other example, if there was a field that represented payload fragment size, then ceiling(PAYLOAD/payload_fragment_size_30) would increment by how many fragments this payload will cause.
"""+mustNone+"""
"""+mustActual+"""
"""
		opts['SEQ']['arg1'] = {'type':'select','title':'Numerator','source':SEQfields,'help':"""
Number to increment by, which will be divided by the Denominator (ceiling)
"""+selhelp+"""
""",'default':'1'}
		opts['SEQ']['arg2'] = {'type':'select','title':'Denominator','source':SEQfields,'help':"""
Number to divide the Numerator by (ceiling)
"""+selhelp+"""
""",'default':'1'}
		opts['SEQ']['arg3'] = {'type':'select','title':'Endian','source':Endians,'help':EndianHelp,'default':'!'}
		
		opts['CHKSUM'] = OrderedDict()
		opts['CHKSUM']['help'] = """
Sets the field to the checksum value of some other field.
"""+mustNone+"""
"""
		opts['CHKSUM']['arg1'] = {'type':'select','title':'algorithm','source':CHKalgs,'help':"""
"""+chkhelp+"""
""",'default':'INET'}
		opts['CHKSUM']['arg2'] = {'type':'select','title':'data source','source':RESTfields,'help':"""
What fields (often REST) to calculate the checksum of
""",'default':'REST'}
		opts['CHKSUM']['arg3'] = {'type':'select','title':'Endian','source':Endians,'help':EndianHelp,'default':'!'}
		
		opts['TIMESTAMP'] = OrderedDict()
		opts['TIMESTAMP']['help'] = """
Sets the field to the current timestamp, plus an offset.
"""+mustNone+"""
"""
		opts['TIMESTAMP']['arg1'] = {'type':'text','title':'Offset (seconds)','help':"""
How many seconds to offset the current timestep by.
Can be a code snippet.
Useful to make a packet seem older than it should be (negative), or newer (positive)
""",'default':'0'}
		opts['TIMESTAMP']['arg2'] = {'type':'select','title':'Endian','source':Endians,'help':EndianHelp,'default':'!'}
		
		return opts

		
		
		
