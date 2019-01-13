Neverwinter Nights Multiplayer protocol Wireshark dissector
===========================================================

This repository contains a lua based wireshark dissector for the
networking protocol utilized by Neverwinter Nights and as far, as 
I can see Neverwinter Nights 2. It is licensed under the terms of 
the [GNU General Public License version 3](https://www.gnu.org/licenses/gpl.html) (or later)
At the moment it is not feature complete and can only recognize the 
pakets necessary for discovering a running game and get some information
from it. It is used as a base for my reverse engineering work to 
reimplement the network protocol for [xoreos](https://xoreos.org). The
nwn networking protocol is divided into two parts, which I call
the lobby protocol and the game protocol. Both have their unique
style and are not related with each other. At the moment, only the lobby
protocol (which is the simpler one) can be read.

How to use
----------

Simply put everything in the source directory into the wireshark plugin
directory which can be found in the About dialog of wireshark.
