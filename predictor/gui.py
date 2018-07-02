#!/usr/bin/python2
from Tkinter import *
from ttk import * # overrides the styles of some (but not all) Tkinter classes
import tkMessageBox, ttk
from tkFileDialog import askdirectory
import time
import os
import subprocess
import sys
from collections import OrderedDict
from lib.helpers import *
import xml.etree.ElementTree as ET

class PredictorGUI(Frame):
	def __init__(self, master,directory):
		Frame.__init__(self,master)
		self.grid(sticky='NSEW')
		
		if str(directory) == "()" or str(directory) == "":
			directory = askdirectory()
		
		problems = ""
		if str(directory) == "()":
			problems += "directory must be non-empty\n\n"
		else:
			if not os.path.isfile(directory+"/packetTypeSequences.txt"):
				problems += "unable to find packetTypeSequences.txt in specified directory: "+directory
			if not os.path.isfile(directory+"/packetsTypes.xml"):
				problems += "unable to find packetTypes.xml in specified directory: "+directory
		if problems != "":
			AlertPop("PredictorGUI arguments issues",problems)
			erlabel = Label(self,text="Error initializing PredictorGUI")
			erlabel.grid(row=0,column=0)
			return
		
		with open(directory+"/packetTypeSequences.txt") as f:
			self.sequence_raw = f.read()
		with open(directory+"/packetsTypes.xml") as f:
			self.typeinfo_raw = f.read()
			
		self.PredictionAnalysis()
		self.PopulateGUI()
		
	def PredictionAnalysis(self):
			
		self.sequence = self.sequence_raw.strip().split(" ")
		self.states = OrderedDict()
		for state in self.sequence:
			self.states[state] = {"ident":state,"trans_out":{},"percs_out":{},"count_out":0,"trans_in":{},"percs_in":{},"count_in":0}
		for state in self.states:
			for substate in self.states:
				self.states[state]["trans_out"][substate] = 0
				self.states[state]["trans_in" ][substate] = 0
				self.states[state]["percs_out"][substate] = ""
				self.states[state]["percs_in" ][substate] = ""
		last = ""
		for state in self.sequence:
			if last != "":
				self.states[last]["trans_out"][state] += 1
				self.states[state]["trans_in"][last] += 1
				self.states[last]["count_out"] += 1
				self.states[state]["count_in"] += 1
			last = state
		for state in self.states:
			self.states[state]["max_trans_out"] = 0
			self.states[state]["max_percs_out"] = ""
			self.states[state]["max_state_out"] = ""
			self.states[state]["max_trans_in"] = 0
			self.states[state]["max_percs_in"] = ""
			self.states[state]["max_state_in"] = ""
			if self.states[state]["count_out"] > 0:				
				for substate in self.states:
					self.states[state]["percs_out"][substate] = str(int(100*self.states[state]["trans_out"][substate]/self.states[state]["count_out"]))+"%"
					if self.states[state]["trans_out"][substate] > self.states[state]["max_trans_out"]:
						self.states[state]["max_trans_out"] = self.states[state]["trans_out"][substate]
						self.states[state]["max_percs_out"] = self.states[state]["percs_out"][substate]
						self.states[state]["max_state_out"] = substate
			if self.states[state]["count_in"] > 0:
				for substate in self.states:
					self.states[state]["percs_in" ][substate] = str(int(100*self.states[state]["trans_in" ][substate]/self.states[state]["count_in" ]))+"%"
					if self.states[state]["trans_in"][substate] > self.states[state]["max_trans_in"]:
						self.states[state]["max_trans_in"] = self.states[state]["trans_in"][substate]
						self.states[state]["max_percs_in"] = self.states[state]["percs_in"][substate]
						self.states[state]["max_state_in"] = substate
		for state in self.states:
			for substate in self.states:
				if self.states[state]["percs_out"][substate] == "0%":
					self.states[state]["percs_out"][substate] = ""
				if self.states[state]["percs_in"][substate] == "0%":
					self.states[state]["percs_in"][substate] = ""
		
		self.typeinfo = ET.fromstring(self.typeinfo_raw)
		self.labellen = 0
		self.datalen = 0
		for state in self.states:
			self.states[state]["label"] = "??"
			self.states[state]["data"] = "??"
		for packet in self.typeinfo:
			state = packet.attrib["type"]
			data = packet.attrib["typeuniq"]
			label = data
			
			datapieces = data.split("=")
			fieldname = datapieces[0]
			for field in packet:
				showname = ""
				mname = ""
				for m in field:
					if m.tag == "mshowname":
						showname = str(m.text).strip()
					if m.tag == "mname":
						mname = str(m.text).strip()
				if mname == fieldname and str(showname) != "":
					label = str(showname)
			
			self.states[state]["label"] = label
			self.states[state]["data"] = data
			self.labellen = max(self.labellen,len(label))
			self.datalen  = max(self.datalen ,len(data))

	def PopulateGUI(self):

		row = ATK_InitRowCounter()
		self.widTabs = ATK_Tabbed(self,row,0)

		col = 0

		self.widTabNextState = ATK_TabbedAdd(self.widTabs,"Next State")
		row = ATK_InitRowCounter()
		
		cols = []
		cols.append({"field":"ident","label":"State"  ,"align":"right"})
		cols.append({"field":"data" ,"label":"Data"   ,"align":"left","width":self.datalen})
		cols.append({"field":"max_state_out","label":"Next"  ,"align":"right","width":4})
		cols.append({"field":"max_percs_out","label":"Chance","align":"right","width":4})
		self.widNextStateTable = ATK_ObjList(self.widTabNextState,row,col,cols,self.openRow)


		self.widTabPrevState = ATK_TabbedAdd(self.widTabs,"Prev State")
		row = ATK_InitRowCounter()
		
		cols = []
		cols.append({"field":"ident","label":"State"  ,"align":"right"})
		cols.append({"field":"data" ,"label":"Data"   ,"align":"left","width":self.datalen})
		cols.append({"field":"max_state_in","label":"Prev"  ,"align":"right","width":4})
		cols.append({"field":"max_percs_in","label":"Chance","align":"right","width":4})
		self.widPrevStateTable = ATK_ObjList(self.widTabPrevState,row,col,cols,self.openRow)


		self.widTabStateInfo = ATK_TabbedAdd(self.widTabs,"State Info")
		row = ATK_InitRowCounter()		
		
		cols = []
		cols.append({"field":"ident","label":"State"  ,"align":"right"})
		cols.append({"field":"label","label":"Name"   ,"align":"left","width":self.labellen})
		cols.append({"field":"data" ,"label":"Data"   ,"align":"left","width":self.datalen})
		cols.append({"field":"count_in" ,"label":"In" ,"align":"right","width":4})
		cols.append({"field":"count_out","label":"Out","align":"right","width":4})
		self.widSInfoTable = ATK_ObjList(self.widTabStateInfo,row,col,cols,self.openRow)
		
		
		self.widTabMatrixC = ATK_TabbedAdd(self.widTabs,"Matrix # Out")
		row = ATK_InitRowCounter()
		
		cols = []
		cols.append({"field":"ident","label":"State","align":"right"})
		cols.append({"field":"data" ,"label":"Data" ,"align":"left","width":self.datalen})
		for state in self.states:
			cols.append({"field":"trans_out_"+state,"label":state,"width":4,"align":"right"})
		self.widMatrixCTable = ATK_ObjList(self.widTabMatrixC,row,col,cols,self.openRow)
		
		
		
		self.widTabMatrixP = ATK_TabbedAdd(self.widTabs,"Matrix % Out")
		row = ATK_InitRowCounter()
		
		cols = []
		cols.append({"field":"ident","label":"State","align":"right"})
		cols.append({"field":"data" ,"label":"Data" ,"align":"left","width":self.datalen})
		for state in self.states:
			cols.append({"field":"percs_out_"+state,"label":state,"width":4,"align":"right"})
		self.widMatrixPTable = ATK_ObjList(self.widTabMatrixP,row,col,cols,self.openRow)
		


		self.widTabMatrixCi = ATK_TabbedAdd(self.widTabs,"Matrix # In")
		row = ATK_InitRowCounter()
		
		cols = []
		cols.append({"field":"ident","label":"State","align":"right"})
		cols.append({"field":"data" ,"label":"Data" ,"align":"left","width":self.datalen})
		for state in self.states:
			cols.append({"field":"trans_in_"+state,"label":state,"width":4,"align":"right"})
		self.widMatrixCiTable = ATK_ObjList(self.widTabMatrixCi,row,col,cols,self.openRow)
		
		
		
		self.widTabMatrixPi = ATK_TabbedAdd(self.widTabs,"Matrix % In")
		row = ATK_InitRowCounter()
		
		cols = []
		cols.append({"field":"ident","label":"State","align":"right"})
		cols.append({"field":"data" ,"label":"Data" ,"align":"left","width":self.datalen})
		for state in self.states:
			cols.append({"field":"percs_in_"+state,"label":state,"width":4,"align":"right"})
		self.widMatrixPiTable = ATK_ObjList(self.widTabMatrixPi,row,col,cols,self.openRow)
		
		
		
		self.widTabRawSeq = ATK_TabbedAdd(self.widTabs,"Raw")
		row = ATK_InitRowCounter()
		
		self.widRawSeq = ATK_TextArea(self.widTabRawSeq,row,col,"Raw Sequence File",self.sequence_raw,80,2)
		self.widRawSeq = ATK_TextArea(self.widTabRawSeq,row,col,"Raw Type Info",self.typeinfo_raw,80,15)
		
		
		for state in self.states:
			obj = self.states[state]
			for substate in self.states:
				obj["trans_out_"+substate] = obj["trans_out"][substate]
				obj["trans_in_" +substate] = obj["trans_in" ][substate]
				obj["percs_out_"+substate] = obj["percs_out"][substate]
				obj["percs_in_" +substate] = obj["percs_in" ][substate]
				
			ATK_ObjList_AddItem(self.widSInfoTable,obj)
			ATK_ObjList_AddItem(self.widMatrixCTable,obj)
			ATK_ObjList_AddItem(self.widMatrixPTable,obj)
			ATK_ObjList_AddItem(self.widMatrixCiTable,obj)
			ATK_ObjList_AddItem(self.widMatrixPiTable,obj)
			ATK_ObjList_AddItem(self.widNextStateTable,obj)
			ATK_ObjList_AddItem(self.widPrevStateTable,obj)
			
		
		
	def openRow(self,stateobj):
		AlertPop("State",stateobj)




# this can be run by-itself, or included as a basic Frame for inclusion in other GUIs
if __name__ == "__main__":
	GUILauncher(PredictorGUI,"Predictor GUI","")
