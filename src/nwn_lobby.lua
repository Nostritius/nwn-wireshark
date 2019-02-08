-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

----------------------------------------
-- Print some values for debugging
print("Wireshark version = ", get_version())
print("Lua version = ", _VERSION)

-- The types of messages
local message_type_descriptions = {
	-- Messages related to the account login
	["BMMA"] = "Unknown Message Type",
	["BMRA"] = "Unknown Message Type",
	["BMPA"] = "Unknown Message Type",

	-- Game information search over broadcast
	["BNES"] = "Game Search Broadcast",
	["BNER"] = "Game Search Response",

	-- Extended information request
	["BNXI"] = "Extended Information Request",
	["BNXR"] = "Extended Information Response",

	-- Pinging for the server
	["BNLM"] = "Ping Request",
	["BNLR"] = "Ping Response",

	-- Description retrieving
	["BNDS"] = "Description Request",
	["BNDR"] = "Description Response"
}

----------------------------------------
-- Create the protocol object
local nwn_lobby = Proto("nwn_lobby", "Neverwinter Nights Multiplayer Lobby Protocol")

----------------------------------------
-- Create the field objects for the protocol

-- thee type of the message
local pf_message_type = ProtoField.string("nwn_lobby.type", "Message Type", base.ASCII, "what type of message is this?")

-- if a message is a server message
local pf_source = ProtoField.int8("nwn_lobby.source", "Message Source", base.RANGE_STRING, {[0] = "Client", [1] = "Server"})

-- BNER Fields
local pf_bner_server_name = ProtoField.string("nwn_lobby.bner.server_name", "Server Name", base.ASCII, "what is the name of the server?")

-- BNXR Fields
local pf_bnxr_min_level        = ProtoField.string("nwn_lobby.bnxr.min_level", "Minimum Level", base.ASCII, "what is the minimum level to join the server?")
local pf_bnxr_max_level        = ProtoField.string("nwn_lobby.bnxr.max_level", "Maximum Level", base.ASCII, "what is the maximum level to join the server?")
local pf_bnxr_current_players  = ProtoField.string("nwn_lobby.bnxr.current_players", "Current Players", base.ASCII, "How many players are already on the server?")
local pf_bnxr_max_players      = ProtoField.string("nwn_lobby.bnxr.max_players", "Maximum Players", base.ASCII, "How many players can join the server?")
local pf_bnxr_local_characters = ProtoField.int8("nwn_lobby.bnxr.local_characters", "Allow local characters", base.RANGE_STRING, {[0] = "No", [1] = "Yes"})
local pf_bnxr_pvp              = ProtoField.int8("nwn_lobby.bnxr.pvp", "Player versus Player", base.RANGE_STRING, {[0] = "None", [1] = "Group", [2] = "Complete"})
local pf_bnxr_player_pause     = ProtoField.int8("nwn_lobby.bnxr.player_pause", "Allow players to pause", base.RANGE_STRING, {[0] = "No", [1] = "Yes"})
local pf_bnxr_only_one_group   = ProtoField.int8("nwn_lobby.bnxr.only_one_group", "Allow only one group", base.RANGE_STRING, {[0] = "No", [1] = "Yes"})
local pf_bnxr_rule_conform     = ProtoField.int8("nwn_lobby.bnxr.rule_conform", "Allow only rule conform characters", base.RANGE_STRING, {[0] = "No", [1] = "Yes"})
local pf_bnxr_item_level       = ProtoField.int8("nwn_lobby.bnxr.item_level", "Allow level condition for items", base.RANGE_STRING, {[0] = "No", [1] = "Yes"})

nwn_lobby.fields = { 
	-- Common fields for every paket
	pf_source,
	pf_message_type,
	
	-- Fields for the BNER paket
	pf_bner_server_name,

	-- Fields for the BNXR paket
	pf_bnxr_min_level,
	pf_bnxr_max_level,
	pf_bnxr_current_players,
	pf_bnxr_max_players,
	pf_bnxr_local_characters,
	pf_bnxr_pvp,
	pf_bnxr_player_pause,
	pf_bnxr_only_one_group,
	pf_bnxr_rule_conform,
	pf_bnxr_item_level
}

----------------------------------------
-- Create the dissector for the nwn lobby 
-- protocol. This function dissects the 
-- datagram into usable pieces of
-- information
function nwn_lobby.dissector(tvbuf, pktinfo, root)
	-- Every packet with a B is a lobby packet
	if tvbuf:range(0, 1):string() ~= "B" then
		return
	end

	-- Set that this paket is part of the nwn lobby protocol and not just
	-- an udp paket.
	pktinfo.cols.protocol:set("NWNLobby")

	-- Get a new tree for the nwn protocol data
	local tree = root:add(nwn_lobby, tvbuf:range(0, pktlen))

	local offset = 0

	-- Read the messages FourCC
	local message_type = tvbuf:range(offset, 4):string()
	offset = offset + 4

    if message_type == "BNDM" then
        return
    end

	-- A small hack to get around the BNERU FiveCC, maybe this U has something to say?
	if tvbuf:range(offset, 1):string() == "U" then
		offset = offset + 1
	end

	local message_type_description = message_type_descriptions[message_type]
	if message_type_description == nil then 
		message_type_description = "Unknown Message Type"
	end

	-- Generate and set an info string
	local info_string = string.format(
		"%s (%s)", 
		message_type, 
		message_type_description
	)
	pktinfo.cols.info:set(info_string)

	local source_type = tvbuf:range(offset, 1):uint()
	offset = offset + 1

	-- Add the common header fields
	tree:add(pf_message_type, message_type)
	tree:add(pf_source, source_type)

	offset = offset + 1

	if message_type == "BNER" then
		offset = offset + 1 -- Unknown data
		local server_name_length = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local server_name = tvbuf:range(offset, server_name_length):string()
		offset = offset + server_name_length
		tree:add(pf_bner_server_name, server_name)
	elseif message_type == "BNXR" then
		offset = offset + 2 -- Unknown data
		local min_level = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local max_level = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local current_players = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local max_players = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local local_characters = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local pvp = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local player_pause = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local only_one_group = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local rule_conform = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		local item_level = tvbuf:range(offset, 1):uint()
		offset = offset + 1
		offset = offset + 1 -- Unknown data
		tree:add(pf_bnxr_min_level, min_level)
		tree:add(pf_bnxr_max_level, max_level)
		tree:add(pf_bnxr_current_players, current_players)
		tree:add(pf_bnxr_max_players, max_players)
		tree:add(pf_bnxr_local_characters, local_characters)
		tree:add(pf_bnxr_pvp, pvp)
		tree:add(pf_bnxr_player_pause, player_pause)
		tree:add(pf_bnxr_only_one_group, only_one_group)
		tree:add(pf_bnxr_rule_conform, rule_conform)
		tree:add(pf_bnxr_item_level, item_level)
	end
end

DissectorTable.get("udp.port"):add(5120, nwn_lobby)
