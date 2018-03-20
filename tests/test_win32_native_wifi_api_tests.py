# coding=utf-8
# win32wifi - Windows Native Wifi Api Python library.
# Copyright (C) 2016 - Shaked Gitelman
#
# Forked from: PyWiWi - <https://github.com/6e726d/PyWiWi>
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
# Author: Andres Blanco     (6e726d)    <6e726d@gmail.com>
# Author: Shaked Gitelman   (almondg)   <shaked.dev@gmail.com>
#

import unittest

import win32wifi.win32_native_wifi_api as win32_native_wifi_api


class TestWin32NativeWifiApi(unittest.TestCase):

    def test_wlan_open_handle_wlan_close_handle_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        result = win32_native_wifi_api.WlanCloseHandle(handle)
        self.assertEqual(result, win32_native_wifi_api.ERROR_SUCCESS)

    def test_wlan_enum_interfaces_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        wlan_ifaces = win32_native_wifi_api.WlanEnumInterfaces(handle)
        data_type = wlan_ifaces.contents.InterfaceInfo._type_
        num = wlan_ifaces.contents.NumberOfItems
        ifaces_pointer = win32_native_wifi_api.addressof(wlan_ifaces.contents.InterfaceInfo)
        wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
        msg = "We expect at least one wireless interface."
        self.assertGreaterEqual(len(wlan_iface_info_list), 1, msg)
        win32_native_wifi_api.WlanFreeMemory(wlan_ifaces)
        win32_native_wifi_api.WlanCloseHandle(handle)

    def test_wlan_scan_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        wlan_ifaces = win32_native_wifi_api.WlanEnumInterfaces(handle)
        data_type = wlan_ifaces.contents.InterfaceInfo._type_
        num = wlan_ifaces.contents.NumberOfItems
        ifaces_pointer = win32_native_wifi_api.addressof(wlan_ifaces.contents.InterfaceInfo)
        wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
        msg = "We expect at least one wireless interface."
        self.assertGreaterEqual(len(wlan_iface_info_list), 1, msg)
        
        ssid = b"test"
        for wlan_iface_info in wlan_iface_info_list:
            win32_native_wifi_api.WlanScan(handle, wlan_iface_info.InterfaceGuid, ssid)

        win32_native_wifi_api.WlanFreeMemory(wlan_ifaces)
        win32_native_wifi_api.WlanCloseHandle(handle)

    def test_wlan_get_network_bss_list_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        wlan_ifaces = win32_native_wifi_api.WlanEnumInterfaces(handle)
        data_type = wlan_ifaces.contents.InterfaceInfo._type_
        num = wlan_ifaces.contents.NumberOfItems
        ifaces_pointer = win32_native_wifi_api.addressof(wlan_ifaces.contents.InterfaceInfo)
        wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
        msg = "We expect at least one wireless interface."
        self.assertGreaterEqual(len(wlan_iface_info_list), 1, msg)
        for wlan_iface_info in wlan_iface_info_list:
            iface_guid = wlan_iface_info.InterfaceGuid
            bss_list = win32_native_wifi_api.WlanGetNetworkBssList(handle, iface_guid)
            msg = "We expect at least one network bss."
            self.assertGreaterEqual(bss_list.contents.NumberOfItems, 1, msg)
        win32_native_wifi_api.WlanFreeMemory(wlan_ifaces)
        win32_native_wifi_api.WlanCloseHandle(handle)

    def test_wlan_get_available_network_list_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        wlan_ifaces = win32_native_wifi_api.WlanEnumInterfaces(handle)
        data_type = wlan_ifaces.contents.InterfaceInfo._type_
        num = wlan_ifaces.contents.NumberOfItems
        ifaces_pointer = win32_native_wifi_api.addressof(wlan_ifaces.contents.InterfaceInfo)
        wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
        msg = "We expect at least one wireless interface."
        self.assertGreaterEqual(len(wlan_iface_info_list), 1, msg)
        for wlan_iface_info in wlan_iface_info_list:
            iface_guid = wlan_iface_info.InterfaceGuid
            network_list = win32_native_wifi_api.WlanGetAvailableNetworkList(handle, iface_guid)
            msg = "We expect at least one network bss."
            self.assertGreaterEqual(network_list.contents.NumberOfItems, 1, msg)
        win32_native_wifi_api.WlanFreeMemory(wlan_ifaces)
        win32_native_wifi_api.WlanCloseHandle(handle)

    def test_wlan_get_profile_list_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        wlan_ifaces = win32_native_wifi_api.WlanEnumInterfaces(handle)
        data_type = wlan_ifaces.contents.InterfaceInfo._type_
        num = wlan_ifaces.contents.NumberOfItems
        ifaces_pointer = win32_native_wifi_api.addressof(wlan_ifaces.contents.InterfaceInfo)
        wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
        msg = "We expect at least one wireless interface."
        self.assertGreaterEqual(len(wlan_iface_info_list), 1, msg)
        for wlan_iface_info in wlan_iface_info_list:
            iface_guid = wlan_iface_info.InterfaceGuid
            profile_info_list = win32_native_wifi_api.WlanGetProfileList(handle, iface_guid)
            msg = "We expect at least one profile info."
            self.assertGreaterEqual(profile_info_list.contents.NumberOfItems, 1, msg)
        win32_native_wifi_api.WlanFreeMemory(wlan_ifaces)
        win32_native_wifi_api.WlanCloseHandle(handle)

    def test_wlan_get_profile_success(self):
        handle = win32_native_wifi_api.WlanOpenHandle()
        wlan_ifaces = win32_native_wifi_api.WlanEnumInterfaces(handle)
        data_type = wlan_ifaces.contents.InterfaceInfo._type_
        num = wlan_ifaces.contents.NumberOfItems
        ifaces_pointer = win32_native_wifi_api.addressof(wlan_ifaces.contents.InterfaceInfo)
        wlan_iface_info_list = (data_type * num).from_address(ifaces_pointer)
        msg = "We expect at least one wireless interface."
        self.assertGreaterEqual(len(wlan_iface_info_list), 1, msg)
        for wlan_iface_info in wlan_iface_info_list:
            iface_guid = wlan_iface_info.InterfaceGuid
            profile_list = win32_native_wifi_api.WlanGetProfileList(handle, iface_guid)
            data_type = profile_list.contents.ProfileInfo._type_
            num = profile_list.contents.NumberOfItems
            profile_info_pointer = win32_native_wifi_api.addressof(profile_list.contents.ProfileInfo)
            profiles_list = (data_type * num).from_address(profile_info_pointer)
            msg = "We expect at least one profile info."
            self.assertGreaterEqual(profile_list.contents.NumberOfItems, 1, msg)
            for profile in profiles_list:
                xml_data = win32_native_wifi_api.WlanGetProfile(handle,
                                                                wlan_iface_info.InterfaceGuid,
                                                                profile.ProfileName)
                msg = "We expect a string of at least 20 bytes."
                self.assertGreater(len(xml_data.value), 20, msg)
        win32_native_wifi_api.WlanFreeMemory(wlan_ifaces)
        win32_native_wifi_api.WlanCloseHandle(handle)


if __name__ == "__main__":
    unittest.main()
