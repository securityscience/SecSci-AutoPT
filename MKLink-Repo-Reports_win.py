# -------------------------------------------- #
#          Sec-Sci AutoPT | 2018-2023          #
# -------------------------------------------- #
# Site:      www.security-science.com          #
# Email:     RnD@security-science.com          #
# Creator:   Arnel C. Reyes                    #
# @license:  GNU GPL 3.0                       #
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM #
# -------------------------------------------- #

import os
import sys
import subprocess

source_folderRepo = r'C:\Sec-Sci_AutoPT\Repo'
destination_folderRepo = r'C:\ProgramData\Jenkins\.jenkins\userContent\Repo'

# Create hard links for files in the source folder
for filename in os.listdir(source_folderRepo):
    source_file = os.path.join(source_folderRepo, filename)
    destination_file = os.path.join(destination_folderRepo, filename)

    if os.path.isfile(source_file) and not os.path.exists(destination_file):
        try:
            subprocess.run(['cmd', '/C', 'mklink', '/H', destination_file, source_file], check=True)
        except subprocess.CalledProcessError as e:
            sys.exit(f"Error creating hard link: {e}")

# Delete existing hard links in the destination folder that no longer exist in the source folder
for filename in os.listdir(destination_folderRepo):
    destination_file = os.path.join(destination_folderRepo, filename)
    source_file = os.path.join(source_folderRepo, filename)

    if os.path.islink(destination_file) and not os.path.exists(source_file):
        os.remove(destination_file)


source_folderReports = r'C:\Sec-Sci_AutoPT\Reports'
destination_folderReports = r'C:\ProgramData\Jenkins\.jenkins\userContent\Reports'

# Create hard links for files in the source folder
for filename in os.listdir(source_folderReports):
    source_file = os.path.join(source_folderReports, filename)
    destination_file = os.path.join(destination_folderReports, filename)

    if os.path.isfile(source_file) and not os.path.exists(destination_file):
        try:
            subprocess.run(['cmd', '/C', 'mklink', '/H', destination_file, source_file], check=True)
        except subprocess.CalledProcessError as e:
            sys.exit(f"Error creating hard link: {e}")

# Delete existing hard links in the destination folder that no longer exist in the source folder
for filename in os.listdir(destination_folderReports):
    destination_file = os.path.join(destination_folderReports, filename)
    source_file = os.path.join(source_folderReports, filename)

    if os.path.islink(destination_file) and not os.path.exists(source_file):
        os.remove(destination_file)

print('Hard links created and stale links deleted successfully.')
