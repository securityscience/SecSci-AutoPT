# ---------------------------------------
# Sec-Sci AutoPT - January 2018
# ---------------------------------------
# Tool:      xBurp Extender v1.0
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# @license:  GNU GPL 3.0
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender
from burp import IHttpListener

import time
import threading

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName("xBurp Sec-Sci AutoPT")

        args = self._callbacks.getCommandLineArguments()
        if '--xBurp' not in args:
            return

        self.packet_timeout = 55
        self.last_packet_seen = int(time.time())
        self._callbacks.registerHttpListener(self)

        print("Vulnerability Scan in progress...")

        scan_thread = threading.Thread(target=self.run_scanStatus)
        scan_thread.start()

    def run_scanStatus(self):
        while int(time.time()) - self.last_packet_seen <= self.packet_timeout:
            # print "(Current Time:",int(time.time()),") - (Last Packet Seen Time:",self.last_packet_seen,") = ",int(time.time())-self.last_packet_seen," <= (Packet Timeout:",self.packet_timeout,")"
            time.sleep(1)

        print("No packets seen in the last", self.packet_timeout, "seconds.")
        print("Removing Listeners...")

        self._callbacks.removeHttpListener(self)

        print("Scan Completed")
        print "Closing Burp..."

        self._callbacks.exitSuite(False)

    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        self.last_packet_seen = int(time.time())
        return