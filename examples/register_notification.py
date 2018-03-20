# import datetime
#
# import asyncio
#
# import win32wifi
#
#
# def demo(wlan_event):
#     if wlan_event != None:
#         print("%s: %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), wlan_event))
#
# @asyncio.coroutine
# def main():
#     ifaces = win32wifi.get_wireless_interfaces()
#     for iface in ifaces:
#         print(iface.guid)
#
#     print("Registering...")
#     win32wifi.register_notification(demo)
#     print("Done.")
#
#     yield from asyncio.Event().wait()
#
#
# if __name__ == "__main__":
#     loop = asyncio.ProactorEventLoop()
#     asyncio.set_event_loop(loop)
#
#     try:
#         loop.run_until_complete(main())
#     except KeyboardInterrupt:
#         pass
#     loop.close()
