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

import functools
import warnings

import xmltodict

import win32_native_wifi_api as native_api

NULL = None

global_callbacks = []
global_handles = []


class WirelessInterface(object):
    def __init__(self, wlan_iface_info):
        self.description = wlan_iface_info.strInterfaceDescription
        self.guid = native_api.GUID(wlan_iface_info.InterfaceGuid)
        self.guid_string = str(wlan_iface_info.InterfaceGuid)
        self.state = wlan_iface_info.isState
        self.state_string = native_api.WLAN_INTERFACE_STATE_DICT[self.state]

    def __str__(self):
        result = ""
        result += "Description: %s\n" % self.description
        result += "GUID: %s\n" % self.guid
        result += "State: %s" % self.state_string
        return result


class InformationElement(object):
    def __init__(self, element_id, length, body):
        self.element_id = element_id
        self.length = length
        self.body = body

    def __str__(self):
        result = ""
        result += "Element ID: %d\n" % self.element_id
        result += "Length: %d\n" % self.length
        result += "Body: %r" % self.body
        return result


class WirelessNetwork(object):
    def __init__(self, wireless_network):
        self.ssid = wireless_network.dot11Ssid.SSID[:native_api.DOT11_SSID_MAX_LENGTH]
        self.profile_name = wireless_network.ProfileName
        self.bss_type = native_api.DOT11_BSS_TYPE_DICT_KV[wireless_network.dot11BssType]
        self.number_of_bssids = wireless_network.NumberOfBssids
        self.connectable = bool(wireless_network.NetworkConnectable)
        self.number_of_phy_types = wireless_network.NumberOfPhyTypes
        self.signal_quality = wireless_network.wlanSignalQuality
        self.security_enabled = bool(wireless_network.SecurityEnabled)
        auth = wireless_network.dot11DefaultAuthAlgorithm
        self.auth = native_api.DOT11_AUTH_ALGORITHM_DICT[auth]
        cipher = wireless_network.dot11DefaultCipherAlgorithm
        self.cipher = native_api.DOT11_CIPHER_ALGORITHM_DICT[cipher]
        self.flags = wireless_network.Flags

    def __str__(self):
        result = ""
        if not self.profile_name:
            self.profile_name = "<No Profile>"
        result += "Profile Name: %s\n" % self.profile_name
        result += "SSID: %s\n" % self.ssid
        result += "BSS Type: %s\n" % self.bss_type
        result += "Number of BSSIDs: %d\n" % self.number_of_bssids
        result += "Connectable: %r\n" % self.connectable
        result += "Number of PHY types: %d\n" % self.number_of_phy_types
        result += "Signal Quality: %d%%\n" % self.signal_quality
        result += "Security Enabled: %r\n" % self.security_enabled
        result += "Authentication: %s\n" % self.auth
        result += "Cipher: %s\n" % self.cipher
        result += "Flags: %d\n" % self.flags
        return result


class WirelessNetworkBss(object):
    def __init__(self, bss_entry):
        self.ssid = bss_entry.dot11Ssid.SSID[:native_api.DOT11_SSID_MAX_LENGTH]
        self.link_quality = bss_entry.LinkQuality
        self.bssid = ":".join(map(lambda x: "%02X" % x, bss_entry.dot11Bssid))
        self.bss_type = native_api.DOT11_BSS_TYPE_DICT_KV[bss_entry.dot11BssType]
        self.phy_type = native_api.DOT11_PHY_TYPE_DICT[bss_entry.dot11BssPhyType]
        self.rssi = bss_entry.Rssi
        self.capabilities = bss_entry.CapabilityInformation
        self.__process_information_elements(bss_entry)
        self.__process_information_elements2()
        self.frequency = bss_entry.ChCenterFrequency

    def __process_information_elements(self, bss_entry):
        self.raw_information_elements = ""
        bss_entry_pointer = native_api.addressof(bss_entry)
        ie_offset = bss_entry.IeOffset
        data_type = (native_api.c_char * bss_entry.IeSize)
        ie_buffer = data_type.from_address(bss_entry_pointer + ie_offset)
        for byte in ie_buffer:
            self.raw_information_elements += str(byte)

    def __process_information_elements2(self):
        MINIMAL_IE_SIZE = 3
        self.information_elements = []
        aux = self.raw_information_elements
        index = 0
        while index < len(aux) - MINIMAL_IE_SIZE:
            eid = ord(aux[index])
            index += 1
            length = ord(aux[index])
            index += 1
            body = aux[index:index + length]
            index += length
            ie = InformationElement(eid, length, body)
            self.information_elements.append(ie)

    def __str__(self):
        result = ""
        result += "BSSID: %s\n" % self.bssid
        result += "SSID: %s\n" % self.ssid
        result += "Link Quality: %d%%\n" % self.link_quality
        result += "BSS Type: %s\n" % self.bss_type
        result += "PHY Type: %s\n" % self.phy_type
        result += "Capabilities: %d\n" % self.capabilities
        result += "Frequency: " + str(self.frequency)
        # result += "Raw Information Elements:\n"
        # result += "%r" % self.raw_information_elements
        result += "\nInformation Elements:\n"
        for ie in self.information_elements:
            lines = str(ie).split("\n")
            for line in lines:
                result += " + %s\n" % line
            result += "\n"
        return result


class WirelessProfile(object):
    def __init__(self, wireless_profile, xml):
        self.name = wireless_profile.ProfileName
        self.flags = wireless_profile.Flags
        self.xml = xml
        self._parse_xml(self.xml)

    def _parse_xml(self, xml):
        d = xmltodict.parse(xml)
        self.ssid = d['WLANProfile']['SSIDConfig']['SSID']['name']

    def __str__(self):
        result = ""
        result += "Profile Name: %s\n" % self.name
        result += "Flags: %d\n" % self.flags
        result += "XML:\n"
        result += "%s" % self.xml
        return result


class MSMNotificationData(object):
    def __init__(self, msm_notification_data):
        assert isinstance(msm_notification_data, native_api.WLAN_MSM_NOTIFICATION_DATA)

        self.connection_mode = native_api.WLAN_CONNECTION_MODE_KV[msm_notification_data.wlanConnectionMode]
        self.profile_name = msm_notification_data.strProfileName
        self.ssid = msm_notification_data.dot11Ssid.SSID[:msm_notification_data.dot11Ssid.SSIDLength]
        self.bss_type = native_api.DOT11_BSS_TYPE_DICT_KV[msm_notification_data.dot11BssType]
        self.mac_addr = ":".join(["{:02x}".format(x) for x in msm_notification_data.dot11MacAddr[:6]])

    def __str__(self):
        result = ""
        result += "Connection Mode: %s\n" % self.connection_mode
        result += "Profile Name: %s\n" % self.profile_name
        result += "SSID: %s\n" % self.ssid
        result += "BSS Type: %s\n" % self.bss_type
        result += "MAC: %s\n" % self.mac_addr
        return result


class ACMConnectionNotificationData(object):
    def __init__(self, acm_notification_data):
        assert isinstance(acm_notification_data, native_api.WLAN_CONNECTION_NOTIFICATION_DATA)

        self.connection_mode = native_api.WLAN_CONNECTION_MODE_KV[acm_notification_data.wlanConnectionMode]
        self.profile_name = acm_notification_data.strProfileName
        self.ssid = acm_notification_data.dot11Ssid.SSID[:acm_notification_data.dot11Ssid.SSIDLength]
        self.bss_type = native_api.DOT11_BSS_TYPE_DICT_KV[acm_notification_data.dot11BssType]
        self.security_enabled = acm_notification_data.bSecurityEnabled

    def __str__(self):
        result = ""
        result += "Connection Mode: %s\n" % self.connection_mode
        result += "Profile Name: %s\n" % self.profile_name
        result += "SSID: %s\n" % self.ssid
        result += "BSS Type: %s\n" % self.bss_type
        result += "Security Enabled: %r\n" % bool(self.security_enabled)
        return result


class WlanEvent(object):
    ns_type_to_codes_dict = {
        native_api.WLAN_NOTIFICATION_SOURCE_NONE: None,
        native_api.WLAN_NOTIFICATION_SOURCE_ONEX: native_api.OneXNotificationTypeEnum,
        native_api.WLAN_NOTIFICATION_SOURCE_ACM: native_api.WlanNotificationACMEnum,
        native_api.WLAN_NOTIFICATION_SOURCE_MSM: native_api.WlanNotificationMSMEnum,
        native_api.WLAN_NOTIFICATION_SOURCE_SECURITY: None,
        native_api.WLAN_NOTIFICATION_SOURCE_IHV: None,
        native_api.WLAN_NOTIFICATION_SOURCE_HNWK: native_api.WlanHostedNetworkNotificationCodeEnum,
        native_api.WLAN_NOTIFICATION_SOURCE_ALL: native_api.OneXNotificationTypeEnum,
    }

    def __init__(self, original, notificationSource, notificationCode, interfaceGuid, data):
        self.original = original
        self.notificationSource = notificationSource
        self.notificationCode = notificationCode
        self.interfaceGuid = interfaceGuid
        self.data = data

    @staticmethod
    def from_wlan_notification_data(wnd):
        actual = wnd.contents
        """
        typedef struct _WLAN_NOTIFICATION_DATA {
            DWORD NotificationSource;
            DWORD NotificationCode;
            GUID  InterfaceGuid;
            DWORD dwDataSize;
            PVOID pData;
        }
        """
        if actual.NotificationSource not in native_api.WLAN_NOTIFICATION_SOURCE_DICT:
            return None

        codes = WlanEvent.ns_type_to_codes_dict[actual.NotificationSource]

        if codes is not None:
            try:
                code = codes(actual.NotificationCode)
                data = WlanEvent.parse_data(actual.pData, actual.dwDataSize, actual.NotificationSource, code)
                if isinstance(data, native_api.WLAN_MSM_NOTIFICATION_DATA):
                    data = MSMNotificationData(data)
                if isinstance(data, native_api.WLAN_CONNECTION_NOTIFICATION_DATA):
                    data = ACMConnectionNotificationData(data)

                event = WlanEvent(actual,
                                  native_api.WLAN_NOTIFICATION_SOURCE_DICT[actual.NotificationSource],
                                  code.name,
                                  actual.InterfaceGuid,
                                  data)
                return event
            except Exception:
                return None

    @staticmethod
    def parse_data(data_pointer, data_size, source, code):
        if data_size == 0 or (
                source != native_api.WLAN_NOTIFICATION_SOURCE_MSM and source != native_api.WLAN_NOTIFICATION_SOURCE_ACM):
            return None

        if source == native_api.WLAN_NOTIFICATION_SOURCE_MSM:
            typ = native_api.WLAN_NOTIFICATION_DATA_MSM_TYPES_DICT[code]
        elif source == native_api.WLAN_NOTIFICATION_SOURCE_ACM:
            typ = native_api.WLAN_NOTIFICATION_DATA_ACM_TYPES_DICT[code]
        else:
            return None

        if typ is None:
            return None

        return WlanEvent.deref(data_pointer, typ)

    @staticmethod
    def deref(addr, typ):
        return typ.from_address(addr)

    def __str__(self):
        return self.notificationCode


class NotificationObject(object):
    def __init__(self, handle, callback):
        self.handle = handle
        self.callback = callback


def getWirelessInterfaces():
    """DEPRICATED => use get_wireless_interfaces
     Returns a list of WirelessInterface objects based on the wireless interfaces available."""
    warnings.warn("this will become depricated, please use get_wireless_interfaces => which has the proper naming convention")
    return get_wireless_interfaces()


def getWirelessNetworkBssList(wireless_interface):
    """DEPRICATED => use get_wireless_networks_bss_list
    Returns a list of WirelessNetworkBss objects based on the wireless networks availables."""
    warnings.warn("this will become depricated, please use get_wireless_networks_bss_list => which has the proper naming convention")
    return get_wireless_networks_bss_list(wireless_interface)


def getWirelessAvailableNetworkList(wireless_interface):
    """DEPRICATED => use get_wireless_available_network_list
    Returns a list of WirelessNetwork objects based on the wireless networks availables."""
    warnings.warn("this will become depricated, please use get_wireless_available_network_list => which has the proper naming "
                  "convention")
    return get_wireless_available_network_list(wireless_interface)


def getWirelessProfileXML(wireless_interface, profile_name):
    """DEPRICATED => use get_wireless_profile_xml"""
    warnings.warn("this will become depricated, please use get_wireless_profile_xml => which has the proper naming convention")
    return get_wireless_profile_xml(profile_name, wireless_interface)


def getWirelessProfiles(wireless_interface):
    """DEPRICATED => use get_wireless_profiles
    Returns a list of WirelessProfile objects based on the wireless profiles."""
    warnings.warn("this will become depricated, please use get_wireless_profiles => which has the proper naming convention")
    return get_wireless_profiles(wireless_interface)


def deleteProfile(wireless_interface, profile_name):
    """DEPRICATED => use delete_profile"""
    warnings.warn("this will become depricated, please use delete_profile => which has the proper naming convention")
    return delete_profile(profile_name, wireless_interface)


def dot11bssidToString(dot11Bssid):
    """DEPRICATED => use dot11_bssid_to_string"""
    warnings.warn("this will become depricated, please use dot11_bssid_to_string => which has the proper naming convention")
    return dot11_bssid_to_string(dot11Bssid)


def wndToStr(wlan_notification_data):
    """DEPRICATED => use wnd_to_str"""
    warnings.warn("this will become depricated, please use wnd_to_str => which has the proper naming convention")
    wnd_to_str(wlan_notification_data)


def OnWlanNotification(callback, wlan_notification_data, p):
    """DEPRICATED => use on_wlan_notification"""
    warnings.warn("this will become depricated, please use on_wlan_notification => which has the proper naming convention")
    on_wlan_notification(callback, wlan_notification_data)


def queryInterface(wireless_interface, opcode_item):
    """DEPRICATED => use query_interface"""
    warnings.warn("this will become depricated, please use query_interface => which has the proper naming convention")
    return query_interface(opcode_item, wireless_interface)


def registerNotification(callback):
    """DEPRICATED => use register_notification"""
    warnings.warn("this will become depricated, please use register_notification => which has the proper naming convention")
    return register_notification(callback)


def unregisterNotification(notification_object):
    """DEPRICATED => use unregister_notification"""
    warnings.warn("this will become depricated, please use unregister_notification => which has the proper naming convention")
    unregister_notification(notification_object)


def unregisterAllNotifications():
    """DEPRICATED => use unregister_all_notifications"""
    warnings.warn("this will become depricated, please use unregister_all_notifications => which has the proper naming convention")
    unregister_all_notifications()


def get_wireless_interfaces():
    """Returns a list of WirelessInterface objects based on the wireless interfaces available."""
    interfaces_list = []
    handle = native_api.WlanOpenHandle()
    wlan_ifaces = native_api.WlanEnumInterfaces(handle)
    # Handle the WlanInterfaceInfoList pointer to get a list of WlanInterfaceInfo structures.
    data_type = wlan_ifaces.contents.InterfaceInfo._type_
    num = wlan_ifaces.contents.NumberOfItems
    ifaces_pointer = native_api.addressof(wlan_ifaces.contents.InterfaceInfo)
    wlan_interface_info_list = (data_type * num).from_address(ifaces_pointer)
    for wlan_interface_info in wlan_interface_info_list:
        wlan_iface = WirelessInterface(wlan_interface_info)
        interfaces_list.append(wlan_iface)
    native_api.WlanFreeMemory(wlan_ifaces)
    native_api.WlanCloseHandle(handle)
    return interfaces_list


def get_wireless_networks_bss_list(wireless_interface):
    """Returns a list of WirelessNetworkBss objects based on the wireless networks availables."""
    networks = []
    handle = native_api.WlanOpenHandle()
    bss_list = native_api.WlanGetNetworkBssList(handle, wireless_interface.guid)
    # Handle the WLAN_BSS_LIST pointer to get a list of WLAN_BSS_ENTRY
    # structures.
    data_type = bss_list.contents.wlanBssEntries._type_
    num = bss_list.contents.NumberOfItems
    bsss_pointer = native_api.addressof(bss_list.contents.wlanBssEntries)
    bss_entries_list = (data_type * num).from_address(bsss_pointer)
    for bss_entry in bss_entries_list:
        networks.append(WirelessNetworkBss(bss_entry))
    native_api.WlanFreeMemory(bss_list)
    native_api.WlanCloseHandle(handle)
    return networks


def get_wireless_available_network_list(wireless_interface):
    """Returns a list of WirelessNetwork objects based on the wireless
       networks availables."""
    networks = []
    handle = native_api.WlanOpenHandle()
    network_list = native_api.WlanGetAvailableNetworkList(handle, wireless_interface.guid)
    # Handle the WLAN_AVAILABLE_NETWORK_LIST pointer to get a list of
    # WLAN_AVAILABLE_NETWORK structures.
    data_type = network_list.contents.Network._type_
    num = network_list.contents.NumberOfItems
    network_pointer = native_api.addressof(network_list.contents.Network)
    networks_list = (data_type * num).from_address(network_pointer)
    for network in networks_list:
        networks.append(WirelessNetwork(network))
    native_api.WlanFreeMemory(network_list)
    native_api.WlanCloseHandle(handle)
    return networks


def get_wireless_profile_xml(profile_name, wireless_interface):
    handle = native_api.WlanOpenHandle()
    xml_data = native_api.WlanGetProfile(handle,
                                         wireless_interface.guid,
                                         native_api.LPCWSTR(profile_name))
    xml = xml_data.value
    native_api.WlanFreeMemory(xml_data)
    native_api.WlanCloseHandle(handle)
    return xml


def get_wireless_profiles(wireless_interface):
    """Returns a list of WirelessProfile objects based on the wireless profiles."""
    profiles = []
    handle = native_api.WlanOpenHandle()
    profile_list = native_api.WlanGetProfileList(handle, wireless_interface.guid)
    # Handle the WLAN_PROFILE_INFO_LIST pointer to get a list of
    # WLAN_PROFILE_INFO structures.
    data_type = profile_list.contents.ProfileInfo._type_
    num = profile_list.contents.NumberOfItems
    profile_info_pointer = native_api.addressof(profile_list.contents.ProfileInfo)
    profiles_list = (data_type * num).from_address(profile_info_pointer)
    xml_data = None  # safety: there may be no profiles
    for profile in profiles_list:
        xml_data = native_api.WlanGetProfile(handle,
                                             wireless_interface.guid,
                                             profile.ProfileName)
        profiles.append(WirelessProfile(profile, xml_data.value))
    native_api.WlanFreeMemory(xml_data)
    native_api.WlanFreeMemory(profile_list)
    native_api.WlanCloseHandle(handle)
    return profiles


def delete_profile(profile_name, wireless_interface):
    handle = native_api.WlanOpenHandle()
    result = native_api.WlanDeleteProfile(handle, wireless_interface.guid, profile_name)
    native_api.WlanCloseHandle(handle)
    return result


def disconnect(wireless_interface):
    handle = native_api.win32_native_wifi_api.WlanOpenHandle()
    native_api.WlanDisconnect(handle, wireless_interface.guid)
    native_api.WlanCloseHandle(handle)


# TODO(shaked): There is an error 87 when trying to connect to a wifi network.
def connect(wireless_interface, connection_params):
    """
        The WlanConnect function attempts to connect to a specific network.

        DWORD WINAPI WlanConnect(
          _In_        HANDLE hClientHandle,
          _In_        const GUID *pInterfaceGuid,
          _In_        const PWLAN_CONNECTION_PARAMETERS pConnectionParameters,
          _Reserved_  PVOID pReserved
        );

        connection_params should be a dict with this structure:
        { "connectionMode": "valid connection mode string",
          "profile": ("profile name string" | "profile xml" | None)*,
          "ssid": "ssid string",
          "bssidList": [ "desired bssid string", ... ],
          "bssType": valid bss type int,
          "flags": valid flag dword in 0x00000000 format }
        * Currently, only the name string is supported here.
    """
    handle = native_api.WlanOpenHandle()
    cnxp = native_api.WLAN_CONNECTION_PARAMETERS()
    connection_mode = connection_params["connectionMode"]
    connection_mode_int = native_api.WLAN_CONNECTION_MODE_VK[connection_mode]
    cnxp.wlanConnectionMode = native_api.WLAN_CONNECTION_MODE(connection_mode_int)
    # determine strProfile
    if connection_mode == ('wlan_connection_mode_profile' or  # name
                           'wlan_connection_mode_temporary_profile'):  # xml
        cnxp.strProfile = native_api.LPCWSTR(connection_params["profile"])
    else:
        cnxp.strProfile = NULL
    # ssid
    if connection_params["ssid"] is not None:
        dot11Ssid = native_api.Dot11Ssid()
        dot11Ssid.SSID = connection_params["ssid"]
        dot11Ssid.SSIDLength = len(connection_params["ssid"])
        cnxp.pDot11Ssid = native_api.pointer(dot11Ssid)
    else:
        cnxp.pDot11Ssid = NULL
    # bssidList
    # NOTE: Before this can actually support multiple entries,
    #   the DOT11_BSSID_LIST structure must be rewritten to
    #   dynamically resize itself based on input.
    if connection_params["bssidList"] is not None:
        bssids = []
        for bssidish in connection_params["bssidList"]:
            bssidish = tuple(int(n, 16) for n in bssidish.split(b":"))
            bssids.append(native_api.DOT11_MAC_ADDRESS(*bssidish))
        bssidListEntries = native_api.c_ulong(len(bssids))
        bssids = (native_api.DOT11_MAC_ADDRESS * len(bssids))(*bssids)
        bssidListHeader = native_api.NDIS_OBJECT_HEADER()
        bssidListHeader.Type = native_api.NDIS_OBJECT_TYPE_DEFAULT
        bssidListHeader.Revision = native_api.DOT11_BSSID_LIST_REVISION_1  # chr()
        bssidListHeader.Size = native_api.c_ushort(native_api.sizeof(native_api.DOT11_BSSID_LIST))
        bssidList = native_api.DOT11_BSSID_LIST()
        bssidList.Header = bssidListHeader
        bssidList.uNumOfEntries = bssidListEntries
        bssidList.uTotalNumOfEntries = bssidListEntries
        bssidList.BSSIDs = bssids
        cnxp.pDesiredBssidList = native_api.pointer(bssidList)
    else:
        cnxp.pDesiredBssidList = NULL  # required for XP
    # look up bssType
    # bssType must match type from profile if a profile is provided
    bssType = native_api.DOT11_BSS_TYPE_DICT_VK[connection_params["bssType"]]
    cnxp.dot11BssType = native_api.DOT11_BSS_TYPE(bssType)
    # flags
    cnxp.dwFlags = native_api.DWORD(connection_params["flags"])
    # print(cnxp)
    result = native_api.WlanConnect(handle,
                                    wireless_interface.guid,
                                    cnxp)
    native_api.WlanCloseHandle(handle)
    return result


def dot11_bssid_to_string(dot11Bssid):
    return ":".join(map(lambda x: "%02X" % x, dot11Bssid))


def query_interface(opcode_item, wireless_interface):
    handle = native_api.WlanOpenHandle()
    opcode_item_ext = "".join(["wlan_intf_opcode_", opcode_item])
    opcode = None
    for key, val in native_api.WLAN_INTF_OPCODE_DICT.items():
        if val == opcode_item_ext:
            opcode = native_api.WLAN_INTF_OPCODE(key)
            break
    result = native_api.WlanQueryInterface(handle, wireless_interface.guid, opcode)
    native_api.WlanCloseHandle(handle)
    r = result.contents
    if opcode_item == "interface_state":
        # WLAN_INTERFACE_STATE
        ext_out = native_api.WLAN_INTERFACE_STATE_DICT[r.value]
    elif opcode_item == "current_connection":
        # WLAN_CONNECTION_ATTRIBUTES
        isState = native_api.WLAN_INTERFACE_STATE_DICT[r.isState]
        wlanConnectionMode = native_api.WLAN_CONNECTION_MODE_KV[r.wlanConnectionMode]
        strProfileName = r.strProfileName
        aa = r.wlanAssociationAttributes
        wlanAssociationAttributes = {
            "dot11Ssid": aa.dot11Ssid.SSID,
            "dot11BssType": native_api.DOT11_BSS_TYPE_DICT_KV[aa.dot11BssType],
            "dot11Bssid": dot11bssidToString(aa.dot11Bssid),
            "dot11PhyType": native_api.DOT11_PHY_TYPE_DICT[aa.dot11PhyType],
            "uDot11PhyIndex": native_api.c_long(aa.uDot11PhyIndex).value,
            "wlanSignalQuality": native_api.c_long(aa.wlanSignalQuality).value,
            "ulRxRate": native_api.c_long(aa.ulRxRate).value,
            "ulTxRate": native_api.c_long(aa.ulTxRate).value,
        }
        sa = r.wlanSecurityAttributes
        wlanSecurityAttributes = {
            "bSecurityEnabled": sa.bSecurityEnabled,
            "bOneXEnabled": sa.bOneXEnabled,
            "dot11AuthAlgorithm": native_api.DOT11_AUTH_ALGORITHM_DICT[sa.dot11AuthAlgorithm],
            "dot11CipherAlgorithm": native_api.DOT11_CIPHER_ALGORITHM_DICT[sa.dot11CipherAlgorithm],
        }
        ext_out = {
            "isState": isState,
            "wlanConnectionMode": wlanConnectionMode,
            "strProfileName": strProfileName,
            "wlanAssociationAttributes": wlanAssociationAttributes,
            "wlanSecurityAttributes": wlanSecurityAttributes,
        }
    else:
        ext_out = None
    return result.contents, ext_out


def wnd_to_str(wlan_notification_data):
    "".join([
        "NotificationSource: %s" % wlan_notification_data.NotificationSource,
        "NotificationCode: %s" % wlan_notification_data.NotificationCode,
        "InterfaceGuid: %s" % wlan_notification_data.InterfaceGuid,
        "dwDataSize: %d" % wlan_notification_data.dwDataSize,
        "pData: %s" % wlan_notification_data.pData,
    ])


def on_wlan_notification(callback, wlan_notification_data):
    event = WlanEvent.from_wlan_notification_data(wlan_notification_data)
    if event is not None:
        callback(event)


def register_notification(callback):
    handle = native_api.WlanOpenHandle()
    c_back = native_api.WlanRegisterNotification(handle, functools.partial(OnWlanNotification, callback))
    global_callbacks.append(c_back)
    global_handles.append(handle)
    return NotificationObject(handle, c_back)


def unregister_notification(notification_object):
    # TODO: Instead of enumerating on the global lists, just save
    # the NotificationObject-s in some list or dict.
    native_api.WlanCloseHandle(notification_object.handle)
    for i, h in enumerate(global_handles):
        if h == notification_object.handle:
            del global_handles[i]
    for i, c in enumerate(global_callbacks):
        if c == notification_object.callback:
            del global_callbacks[i]


def unregister_all_notifications():
    for handle in global_handles:
        native_api.WlanCloseHandle(handle)
    del global_handles[:]
    del global_callbacks[:]
