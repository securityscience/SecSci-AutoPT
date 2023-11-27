# ---------------------------------------
# Sec-Sci AutoPT v3.2311 - January 2018
# ---------------------------------------
# Tool:      xReport Extender v1.0
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM

from burp import IBurpExtender
from java.io import File

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("xReport Sec-Sci AutoPT")
        args = callbacks.getCommandLineArguments()

        if '--xReport' not in args:
            return

        report_format = args[1]
        file_name = args[2]
        issues = callbacks.getScanIssues('')

        if report_format == 'html':
            callbacks.generateScanReport(report_format, issues, File(file_name + '.html'))
        elif report_format == 'xml':
            callbacks.generateScanReport(report_format, issues, File(file_name + '.xml'))
        else:
            callbacks.generateScanReport('html', issues, File(file_name + '.html'))
            callbacks.generateScanReport('xml', issues, File(file_name + '.xml'))

        callbacks.exitSuite(False)

