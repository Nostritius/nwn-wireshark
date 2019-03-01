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
-- Create the protocol object
local nwn_game = Proto("nwn_game", "Neverwinter Nights Multiplayer Game Protocol")

----------------------------------------
-- Create the dissector for the nwn game
-- protocol. This function dissects the
-- datagram into usable pieces of
-- information
function nwn_game.dissector(tvbuf, pktinfo, root)
    -- Set that this paket is part of the nwn game protocol and not just
    -- an udp paket.
    pktinfo.cols.protocol:set("NWNGame")

    -- Get a new tree for the nwn protocol data
    local tree = root:add(nwn_game, tvbuf:range(0, pktlen))
end

----------------------------------------
-- Register heuristic function to separate
-- lobby packets from game packets
local function nwn_game_magicid(tvbuf, pktinfo, root)
    if tvbuf:range(0, 1):string() == "M" then
        nwn_game.dissector(tvbuf, pktinfo, root);
        return true
    end
    return false
end

nwn_game:register_heuristic("udp", nwn_game_magicid)
