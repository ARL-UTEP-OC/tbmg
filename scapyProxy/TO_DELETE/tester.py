#import interceptor
from scapy.all import *
import psocket
'''

def verdict_cb(ll_data, ll_proto_id, data, ctx):
    print 'll_data',ll_data
    print 'proto',ll_proto_id
    print 'data',data
    print 'ctx',ctx
    print 'ETHER'
    eth = Ether(ll_data)
    eth.show()
    print 'IP'
    ip = IP(data)
    ip.show()

intercept = interceptor.Interceptor()
intercept.start(verdict_cb,queue_ids=[0,1,2])
print 'started!!!'
time.sleep(200)
intercept.stop()
'''
psock = psocket.SocketHndl(mode=psocket.SocketHndl.MODE_LAYER_2, timeout=20)
for raw_bytes in psock:
    print 'raw:',raw_bytes.encode('hex')
    eth = Ether(raw_bytes)
    eth.show()
psock.close()