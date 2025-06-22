# ----------------------------------------------
# Sec-Sci xBurp Extender v2.0.250602 - June 2025
# ----------------------------------------------
# Tool:      xBurp Extender v2.0.250602
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2018-2025 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender
from burp import IHttpListener
from java.lang import Thread as JThread
import time, threading


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName("xBurp Sec-Sci AutoPT v2")

        args = self._callbacks.getCommandLineArguments()
        if '--xBurp' not in args:
            return

        self.packet_timeout = 88
        self.last_packet_seen = int(time.time())
        self._callbacks.registerHttpListener(self)

        print("Vulnerability Scan in progress...")

        scan_thread = threading.Thread(target=self.run_scanStatus)
        scan_thread.start()

    def run_scanStatus(self):
        sec_sci_threads = []
        while int(time.time()) - self.last_packet_seen <= self.packet_timeout or len(sec_sci_threads) > 0:
            # print("(Current Time:", int(time.time()), ") - (Last Packet Seen Time:", self.last_packet_seen, ") = ",
            #       int(time.time()) - self.last_packet_seen, " <= (Packet Timeout:", self.packet_timeout, ")")
            try:
                threads = self.get_all_threads()
                # self._callbacks.printOutput("[*] --- JVM Thread Dump (Filtered SecSci Threads) ---")

                sec_sci_threads = []

                for t in threads:
                    if t is None:
                        continue
                    try:
                        name = t.getName() if t.getName() else "<unnamed>"
                        alive = t.isAlive()
                        # daemon = t.isDaemon()
                        # tid = t.getId()
                        # state = t.getState()

                        if name.startswith("SecSci") and alive:
                            # self._callbacks.printOutput(
                            #     "  - Name: '{}', Alive: {}, Daemon: {}, ID: {}, State: {}".format(
                            #         name, alive, daemon, tid, state))
                            sec_sci_threads.append(t)

                    except Exception as e:
                        self._callbacks.printError("Failed to read thread info: {}".format(e))
                # Print number of SecSci threads:
                # self._callbacks.printOutput("[*] SecSci threads detected: {}".format(len(sec_sci_threads)))

            except Exception as e:
                self._callbacks.printError("Thread checker error: {}".format(e))

            time.sleep(3)

        print("No scan packets and SecSci threads seen in the last", self.packet_timeout, "seconds.")
        print("Removing Listeners...")

        self._callbacks.removeHttpListener(self)

        print("Scan Completed")
        print("Closing Burp...")

        self._callbacks.exitSuite(False)

    def get_all_threads(self):
        # Java Thread.getAllStackTraces() gets all live threads
        return JThread.getAllStackTraces().keySet().toArray()

    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        self.last_packet_seen = int(time.time())
        return