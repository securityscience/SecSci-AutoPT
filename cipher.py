# ---------------------------------------
# Sec-Sci AutoPT v3.2311 - January 2018
# ---------------------------------------
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# @license:  GNU GPL 3.0
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM

# Download and Install GnuPG
# https://www.gpg4win.org/download.html
# https://www.gnupg.org/download/index.html

# pip install python-gnupg
# pip install pywin32

from cryptography.fernet import Fernet
import subprocess
import gnupg
import os
if os.name == 'nt':
    import win32cred
    import winreg
else:
    import keyring


def keys_key(key):

    where, location = str(key).split('=')
    where = str(where).lower()
    if where == 'wcm':
        try:
            credential = win32cred.CredRead(location, win32cred.CRED_TYPE_GENERIC, 0)
            # username = credential["UserName"]
            password = credential["CredentialBlob"].decode("utf-16")
            return password
        except Exception as e:
            print(f"Error retrieving credential: {e}")
            return None, None
    elif where == 'kr':
        service_name, username = str(location).split(',')
        return keyring.get_password(service_name, username)
    elif where == 'env':
        return os.environ.get(location)
    elif where == 'fs':
        try:
            with open(location, 'r') as file:
                return file.read()
        except FileNotFoundError:
            print(f"The file '{location}' does not exist.")
        except Exception as e:
            print(f"An error occurred: {e}")
    elif where == 'reg':
        hive, subkey, value_name = str(location).split(',')
        hive = str(hive).lower()
        if hive == 'HKU': hive = winreg.HKEY_USERS
        if hive == 'HKCU': hive = winreg.HKEY_CURRENT_USER
        if hive == 'HKCR': hive = winreg.HKEY_CLASSES_ROOT
        if hive == 'hklm': hive = winreg.HKEY_LOCAL_MACHINE
        if hive == 'HKCC': hive = winreg.HKEY_CURRENT_CONFIG

        try:
            key = winreg.OpenKey(hive, subkey)
            value, data_type = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return value
        except FileNotFoundError:
            print(f"\nRegistry key not found: {subkey}")
        except Exception as e:
            print(f"\nAn error occurred: {e}")


def secrets_key(java_dir, secrets_dir, key):
    secrets_cipher = keystore_data(java_dir,
                                   os.path.join(secrets_dir, 'Keys.jks'),
                                   keys_key(key),
                                   'secrets')

    the_masterkey = masterkey(java_dir, secrets_dir, key)
    the_secrets_key = decrypt_data(secrets_cipher, the_masterkey)

    return the_secrets_key


def masterkey(java_dir, secrets_dir, key):
    the_masterkey = keystore_data(java_dir,
                                  os.path.join(secrets_dir, 'Keys.jks'),
                                  keys_key(key),
                                  'masterkey')
    return the_masterkey


def encryption_key(java_dir, secrets_dir, key):
    the_secrets_key = secrets_key(java_dir, secrets_dir, key)

    the_masterkey = masterkey(java_dir, secrets_dir, key)

    gpg_passphrase_cipher = keystore_data(java_dir,
                                          os.path.join(secrets_dir, 'Secrets.jks'),
                                          the_secrets_key,
                                          'gpgpassphrase')

    gpg_passphrase = decrypt_data(gpg_passphrase_cipher, the_masterkey)

    return gpg_passphrase


def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(data.encode())
    return cipher_text


def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    except Exception:
        return
    return decrypted_data


def encrypt_file(gpg_dir, input_file, output_file, passphrase):
    gpg = gnupg.GPG(gpgbinary=os.path.join(gpg_dir, 'gpg'))

    try:
        with open(input_file, 'rb') as f:
            enc = gpg.encrypt_file(f, passphrase=passphrase, symmetric=True, recipients=[], output=output_file)
        return enc.ok
    except Exception as e:
        print(e)
        return False


def decrypt_file(gpg_dir, input_file, output_file, passphrase):
    gpg = gnupg.GPG(gpgbinary=os.path.join(gpg_dir, 'gpg'))

    try:
        with open(input_file, 'rb') as f:
            dec = gpg.decrypt_file(f, passphrase=passphrase, output=output_file)
        return dec.ok
    except Exception as e:
        print(e)
        return False


def keystore_data(java_dir, keystore_path, keystore_password, keystore_alias):
    data = subprocess.run([os.path.join(java_dir, 'java'), 'KeyStoreData',
                           keystore_path, keystore_password, keystore_alias],
                          capture_output=True, text=True)
    return data.stdout.strip()


def export_pkcs12(java_dir, keystore_path, keystore_password,
                  src_alias, pkcs12_file, pkcs12_password,
                  dest_alias, key_password):

    subprocess.run(f'{os.path.join(java_dir, "keytool")} -importkeystore -srckeystore {keystore_path} ' +
                   f'-srcstorepass {keystore_password} -srcalias {src_alias} -destkeystore ' +
                   f'{pkcs12_file} -deststoretype PKCS12 -deststorepass {pkcs12_password} ' +
                   f'-destalias {dest_alias} -srckeypass {key_password}', input='yes\n', encoding='utf-8')
