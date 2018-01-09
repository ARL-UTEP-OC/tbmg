import scapy.utils

#####################################################################################

# Currently ignore littleEndian, unitSize #
def packetSequenceNoIncrement(inputBuffer, sizeOfBuffer, littleEndian, unitSize, outputSize, outputBuffer):
	# Check to make sure only sizeOfBuffer bytes from the beginning are processed. Cut the rest off. #
	if len(inputBuffer) != sizeOfBuffer:
		inputBuffer = inputBuffer[:sizeOfBuffer]
	
	# Convert string to hex int, add one to it & join it back to string #
	result = list(inputBuffer)
	outputBuffer = hex(int(inputBuffer, 16) + 1)
	outputBuffer = "".join(outputBuffer)[2:]
	
	# Make sure outputBuffer is good #
	outputBuffer = editOuputBuffer(outputBuffer, outputSize)
		
	return outputBuffer
	
#####################################################################################

# Currently ignore littleEndian, unitSize #
def packetCalcChecksum(inputBuffer, sizeOfBuffer, littleEndian, unitSize, outputSize, outputBuffer):
	# Check to make sure only sizeOfBuffer bytes from the beginning are processed. Cut the rest off. #
	if len(inputBuffer) != sizeOfBuffer:
		inputBuffer = inputBuffer[:sizeOfBuffer]
	
	# Calculate the checksum value of the packet #
	outputBuffer = str(hex(scapy.utils.checksum(inputBuffer.decode('hex'))))[2:]
	
	# Make sure outputBuffer is good #
	outputBuffer = editOuputBuffer(outputBuffer, outputSize)
	
	return outputBuffer
	
#####################################################################################

# Check to make sure output is the expected size and edit if not #
def editOuputBuffer(buf, size):
	buf1 = buf
	
	if len(buf1) > size:
		buf1 = buf1[-size:]
	elif len(buf1) < size:
		while len(buf1) < size:
			buf1 = '0' + buf1
	
	return buf1

#print packetCalcChecksum('0800000010410025035685570000000040020a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 128, True, 'byte', 4, '')
print packetSequenceNoIncrement('01f1', 4, True, 'byte', 4, '')
