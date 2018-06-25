import sys
import os
from scapy.all import *

org_packet_path = '/root/tbmg/scapyProxy/org_packet.txt'
packet_feilds_path = '/root/tbmg/scapyProxy/packet_feilds.txt'

def text_to_scapy_value(feild_name,feild_value,layer_name,org_packet):
	type1 = getattr(org_packet[layer_name],feild_name)
	type2 = None
	value = None
	feild_value = feild_value.strip()
	try:
		value = str(int(feild_value))
	except:
		value = str(feild_value)
		try:
			value = '"'+value.encode('utf8')+'"'
		except:
			if type1==int:
				value = int(value.encode('hex'),16)
			else:
				value = '"' +value.decode('hex')+'"'
	try:
		if type(value) == str and type1==str:
			if int(value[1:-1],16):
				value = '"' + value[1:-1].decode('hex') + '"'
	except Exception:
		pass
	if '[' in value and ']'in value:
		value = value[1:-1]
	elif value == '"None"':
		if type1 == type(None):
			pass
		elif type1 == int:
			value = '0'
		else:
			value = 'None'
	elif value == '""':
		value = 'None'
	if layer_name == 'Raw' and feild_name == 'load':
		try:
			return value[1:-1].decode('hex')
		except:
			pass
	return value

def main():
	s = sys.stdin.read().split("\n") #"64\n".split("\n")
	if os.path.isfile(org_packet_path) and os.path.isfile(packet_feilds_path):
		packet_feilds = eval(open(packet_feilds_path, 'r').read())
		try:
			pkt = IP(open(org_packet_path, 'r').read().decode("hex"))
			i = 0
			for feild in packet_feilds:
				val = text_to_scapy_value(feild[1],s[i],feild[0],pkt)
				setattr(pkt[feild[0]],feild[1],getattr(pkt[feild[0]],feild[1]).__class__(val))
				i+=1
			try:
				del (self.current_pack['IP'].chksum)
			except:
				pass
			try:
				del (self.current_pack['TCP'].chksum)
			except:
				pass
			resp = sr1(pkt, timeout=4, verbose=0)
			print (resp.summary())
		except Exception as e:
			print (repr(e))
	else:
		try:
			pkt = IP(s.decode('hex'))
			resp = sr1(pkt, timeout=4, verbose=0)
			print (resp.summary())
		except Exception as e:
			print (repr(e))

if __name__ == "__main__":
	import afl
	afl.start()
	main()
