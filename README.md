TBMG (Traffic Based Model Generator)

INSTALLATION

	apt-get install graphviz
	apt-get install matplotlib

	locate init.lua
		expect to find these lines in /etc/wireshark/init.lua
		original settings/lines:
			run_user_scripts_when_superuser = false
			if running_superuser then
			disable_lua = false
		change/ensure these settings/lines:
			run_user_scripts_when_superuser = true
			if false && running_superuser then
			disable_lua = false


USAGE

	python TBMG2.py
	
EXAMPLE - CREATE PROTOCOL MODEL (ICMP)

	In "Model Generation" tab:
		Protocol Name: icmp (this may have to match the dissector)
		Pcap File Path: sampleConfigs/10secs.pcap (find it quickly with Choose File)
		leave Dissector blank
		Keyword: Type
		Model-Name: icmp (this can be named different from the protocol, such as adding your initials for a custom version)
		then click Create
		you will be taken to the "View Model" tab, if successful. Otherwise, check terminal for errors.

EXAMPLE - LOAD EXISTING PROTOCOL MODEL

	In "Model Generation" tab:
		use the dropdown to browse existing protcols.  Find "ICMP" if you ran last example.
		then click Load
		you will be taken to the "View Model" tab.

EXAMPLE - VIEW PROTOCOL MODEL INSTANCE

	Once in "View Model" tab (get here from previous Create or Load):
		Use "Select Model" to select one of the protocol's variants (keyed off of the "keyword" earlier)
		Select wrapper from the "Create" selector.  RAW will provide a layer 2 (IP) wrapper.  TCP and UDP will provide a layer 3 wrapper around the IP wrapper.
		Click "View" to see what its default values look like in scapy
		Click "Edit" to manipulate those values, which takes you to the "Edit Model" tab

EXAMPLE - EDIT PROTOCOL MODEL INSTANCE

	Using "icmp_example"...
	Open Wireshark, and set it to listen (on "any" interface)...
		use the "ping" command in a terminal to see an ICMP request and response in Wireshark
	Run TBMG:
		python TBMG2.py
	In "Model Generation" tab:
		select "icmp_example" from the "Select Model..." dropdown
		click "Load", which will take you to the next tab
	In "View Model" tab:
		for "Select Model" select "icmp_exampleType8" (the "request" ICMP ping echo)
		for "Create" select "RAW"
		click "Edit", which will take you to the next tab
	In "Edit Model" tab:
		set values to mimic an actual ICMP request
		set the "dst" address to same system you targeted with "ping"
		set the "src" address to the same address you can see for yourself in Wireshark
		set the "IP" "proto" field to "0x1" which is the ICMP protocol identifier
		...TODO: figure out what else is missing...
		click "Send" to send the ICMP request
		use Wireshark to see that the request was sent (and hopefully the response to it)

EXAMPLE - EDIT PROTOCOL MODEL CLASS

	Using "whb_icmp"...
	In "Edit Model" tab:
		click "Send" a few times, you'll notice "icmp_code_35" and "data_data_50" get randomized values
		so, we'll make sure that the checksum and sequence are updating too...
		click "Edit" next to the icmp_checksum_36, which will take you to the next tab
	In "Adv. Field" tab:
		Ensure that it's "Run after" is set to sometime after "data_data_50"
		Notice that "CHKSUM" is currently selected (if not, select it)
		Click "Save and Close" if you made changes, you'll return to the previous tab
	In "Edit Model" tab:
		click the "N" button next to icmp_checksum_36 value field, this will change it to "None"
		click "Update" to save the change
		click "Send" a few times, now you should notice the checksum changes each time...
		...this is because "None" tells the code that it is safe to dynamically change the value
		let's use that same principle to allow the sequence to update...
		click the "N" button next to icmp_seq_40, changing it to "None" to allow it to run its logic
		click "Update" to save the change
		click "Send" a few times, now you should notice the sequence changing each time
		notice some buttons are a different color, those have special dynamic behavior...
		... so set them to "None" to see them change too.
		Notice icmp_code_35 ignores whether it is set to None, which can make it dangerous, and is an example of what not to do!


QUESTIONS

	What is a good way for user to know what values of "Keyword" are valid/useful?
	
	Should we able to re-run/overwrite a protocol/model?  (currently can't) If not, add GUI warning that name is not available.
	
	
