import sys
from scapy.all import *
def main():
	s = sys.stdin.read()
	try:
		pkt = IP(s.decode("hex"))
		pkt.time = 1529816004.61
		resp = sr1(pkt)
		print resp.summary()
	except Exception as e:
		print repr(e)

if __name__ == "__main__":
	import afl
	afl.start()
	main()
