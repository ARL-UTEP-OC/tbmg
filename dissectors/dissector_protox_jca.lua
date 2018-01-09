----------------------------------------
-- script-name: protox_dissector.lua
--
--
----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    port         = 65333,
    heur_enabled = false,
}

-- for testing purposes, we want to be able to pass in changes to the defaults
-- from the command line; because you can't set lua preferences from the command
-- line using the '-o' switch (the preferences don't exist until this script is
-- loaded, so the command line thinks they're invalid preferences being set)
-- so we pass them in as command arguments insetad, and handle it here:
local args={...} -- get passed-in args
if args and #args > 0 then
    for _, arg in ipairs(args) do
        local name, value = arg:match("(.+)=(.+)")
        if name and value then
            if tonumber(value) then
                value = tonumber(value)
            elseif value == "true" or value == "TRUE" then
                value = true
            elseif value == "false" or value == "FALSE" then
                value = false
            elseif value == "DISABLED" then
                value = debug_level.DISABLED
            elseif value == "LEVEL_1" then
                value = debug_level.LEVEL_1
            elseif value == "LEVEL_2" then
                value = debug_level.LEVEL_2
            else
                error("invalid commandline argument value")
            end
        else
            error("invalid commandline argument syntax")
        end

        default_settings[name] = value
    end
end

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------
-- creates a Proto object, but doesn't register it yet
--local dns = Proto("mydns","MyDNS Protocol")
local protox_proto = Proto("protox", "Clear Text Protocol X");


local message_types = {
	[     1] = "Status Request",
	[     2] = "Status Response",
	[     3] = "Shutdown Request",
	[     4] = "Shutdown Response",
	[     5] = "Alarm Notification",
	[     6] = "Event Notification",
	[     7] = "Protocol/Message Set Identification Request",
	[     8] = "Protocol/Message Set Identification Response",
	[     9] = "Keep Alive",
	[    10] = "Version Request",
	[    11] = "Version Response",
	[    14] = "Display Request",
	[    15] = "Display Response",
	[    17] = "Friendly SA Data",
	[    18] = "Observed Data",
	[    20] = "Equipment Status Request",
	[    21] = "Equipment Status Response",
	[    22] = "Request Platform Logistic Status",
	[    23] = "Platform Logistics Status Response",
	[    24] = "Remote Display Control",
	[    25] = "Services Registration",
	[    26] = "VNC Server Config",
	[    27] = "Local Display Selection",
	[    28] = "VNC Client Configuration",
	[    29] = "Failsafe Configuration",
	[    30] = "Display Server Query",
	[    31] = "Display Server Response",
	[    37] = "Call for Support Message",
	[    38] = "Logon Notification",
	[    41] = "Logoff Notification",
	[    42] = "PVT Message Rate",
	[    43] = "Logon Notification Response",
	[    44] = "Logoff Notification Response",
	[    46] = "Platform Type",
	[    47] = "Gumball Display Request",
	[    48] = "Alert Display",
	[    49] = "Alert Clear",
	[    50] = "JBC-P/JCR URN",
	[    51] = "Slew to Cue",
	[    70] = "Netted Asset Interface Protocol",
	[    71] = "JBC-P Interface Protocol",
	[   125] = "Extended Services Registration",
	[  5000] = "Absolute Target Position Message",
	[  5001] = "Relative Target Position Message",
	[  5040] = "Position Velocity and Time",
	[ 10003] = "Time Mark 3 Message",
	[ 15045] = "Waypoint Information Message",
	[ 16000] = "Steer-To-Point",
	[ 16010] = "Steer-To-Control",
	[ 16020] = "Engagement Report Message",
	[ 16030] = "Position and Time Message",
	[100003] = "Shutdown Request",
	[100004] = "Shutdown Response",
	[100026] = "VNC Server Configuration",
	[100028] = "VNC Client Configuration",
	[100029] = "Failsafe Configuration",
	[105040] = "Position Velocity and Time"
}

local preamble = ProtoField.bytes("protox.preamble", "Preamble")
local msgid = ProtoField.uint32("protox.msgid", "Message Id", base.DEC, message_types)
local msglen = ProtoField.uint32("protox.msglen", "Message Length")
local msgnum = ProtoField.uint32("protox.msgnum", "Message Number")
local data = ProtoField.bytes("protox.data", "Data")
----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set dns.fields to it, so as to avoid forgetting a field
protox_proto.fields = { preamble, msgid, msglen, msgnum, data}

----------------------------------------
---- some constants for later use ----
-- the PROTOX header size
local PROTOX_HDR_LEN = 16

----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "dns.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function protox_proto.dissector(buffer, pinfo, tree)

-- set the protocol column to show our protocol name
    pinfo.cols.protocol:set("PROTOX")
    
	local pktlen = buffer:reported_length_remaining()
	local subtree = tree:add(protox_proto, buffer:range(0,pktlen))
    
    -- now let's check it's not too short
    if pktlen < PROTOX_HDR_LEN then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        -- the old way: tree:add_expert_info(PI_MALFORMED, PI_ERROR, "packet too short")
        -- the correct way now:
        dprint("packet length",pktlen,"too short")
        return
    end
    
	local preamble_range = buffer:range(0,4)
	--local preamble_range_value = preamble_range:__tostring()
	subtree:add(preamble, preamble_range)
	subtree:append_text(", Message Preamble: " .. preamble_range)

	local msgid_range = buffer:range(4,4)
	local msgid_range_value = msgid_range:uint()
	subtree:add(msgid, msgid_range)
	subtree:append_text(", Message Id: " .. msgid_range_value)

	local msgtype
	if message_types[msgid_range_value] then
		msgtype = message_types[msgid_range_value]
	else
		msgtype = "UNKNOWN"
	end
	subtree:append_text("(" .. msgtype .. ")")
	
	local msglen_range = buffer:range(8,4)
	local msglen_range_value = msglen_range:uint()
	subtree:add(msglen, msglen_range)
	subtree:append_text(", Message Length: " .. msglen_range_value)

	local msgnum_range = buffer:range(12,4)
	local msgnum_range_value = msgnum_range:uint()
	subtree:add(msgnum, msgnum_range)
	subtree:append_text(", Message Number: " .. msgnum_range_value)

	local pos = PROTOX_HDR_LEN
	local pktlen_remaining = pktlen - pos

	--if there are any remaining bytes, consider them data
	if pktlen_remaining > 0 then
		--get the rest of the packet data
		local pktlen_remaining = pktlen - pos
		
		local data_range = buffer:range(pos,pktlen_remaining)
		local data_range_value = data_range:bytes()
		subtree:add(data, data_range)
		--subtree:append_text(", Data: " .. data_range_value)
	end
	
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9100, protox_proto)
tcp_table:add(9120, protox_proto)
