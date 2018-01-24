from Tkinter import *


class fieldObj:
	
	def __init__(self, name, value, layer):
		self.id = ""
		self.name=name
		self.value=value
		self.layer=layer
		self.TKfieldName = None
		self.TKfieldValue = None
		self.constraint=""
		self.dependency=""
	
	def setValue(self, newValue):
		self.value=newValue
		
	def setTKName(self, label):
		self.TKfieldName = label
		
	def setTKValue(self, label):
		self.TKfieldValue = label
		
	def toString(self):
		print "id= "+repr(self.id)+", name= "+repr(self.name)+", value= "+repr(self.value)+", layer= "+ repr(self.layer)+ ", TKfieldName= "+repr(self.TKfieldName)+ ", TKfieldValue= "+repr(self.TKfieldValue)+", constraint= "+repr(self.constraint)+", dependency= "+repr(self.dependency)
	
	
	
		
