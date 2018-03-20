# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - Shaked Gitelman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Shaked Gitelman   (almondg)   <shaked.dev@gmail.com>
#

from win32wifi import disconnect
from win32wifi import get_wireless_available_network_list
from win32wifi import get_wireless_interfaces

if __name__ == "__main__":
    ifaces = get_wireless_interfaces()
    print(ifaces)
    print(len(ifaces))
    for iface in ifaces:
        disconnect(iface)
        print(iface)
        guid = iface.guid
        networks = get_wireless_available_network_list(iface)
        print()
        for network in networks:
            print(network)
            print("-" * 20)
        print()
