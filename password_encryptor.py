# ---------------------------------------
# Sec-Sci AutoPT v3.2311 - January 2018
# ---------------------------------------
# Tool:      Password Encryptor v1.0
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM

# pip install cryptography


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import configparser
import subprocess
import argparse
import getpass
import base64
import cipher
import os
import re


def initialize_config(config_path, config_section='Settings'):
    set_config_settings = {}

    config = configparser.ConfigParser()
    config.read(config_path)

    if config_section in config:
        settings_section = config[config_section]

        # Update the global dictionary with the configuration variables
        for key, value in settings_section.items():
            set_config_settings[key] = eval(value)
        return set_config_settings
    else:
        print(f"Error: '{config_section}' section not found in the configuration file.")
        return


# Generate a masterkey from the masterkey password
def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Choose an appropriate number of iterations
        salt=salt,
        length=32  # key length in bytes
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)


# Generate a random key
def generate_random_key():
    return Fernet.generate_key()


# Save the key to a file
def save_key(key, key_file='password.key'):
    with open(key_file, 'wb') as key_file:
        key_file.write(key)


# Load the key from a file
def load_key(key_file='password.key'):
    return open(key_file, 'rb').read()


# Encrypt data using the key
def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(data.encode())
    return cipher_text


# Decrypt data using the key
def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data


# Save encrypted password to a file
def save_password(password, key, pass_file='password.dat'):
    encrypted_password = encrypt_data(password, key)
    with open(pass_file, 'wb') as password_file:
        password_file.write(encrypted_password)


# Retrieve and decrypt password from the file
def retrieve_password(key, pass_file='password.dat'):
    with open(pass_file, 'rb') as password_file:
        encrypted_password = password_file.read()
    decrypted_password = decrypt_data(encrypted_password, key)
    return decrypted_password


def import_data_to_keystore(keystore, alias, value):
    config_settings = initialize_config('autopt.conf')

    if not config_settings:
        print('Config Settings Initialization Error...')
        exit()

    for operating_dir in [('secrets_dir', os.path.join(os.getcwd(), 'Secrets'))]:

        if not config_settings[operating_dir[0].strip()]:
            config_settings[operating_dir[0]] = operating_dir[1]

    encryption_mode = str(config_settings['encryption_mode']).lower()
    java_dir = config_settings['java_dir']
    secrets_dir = config_settings['secrets_dir']

    for operating_dir in [('secrets_dir', os.path.join(os.getcwd(), 'Secrets'))]:
        if not config_settings[operating_dir[0].strip()]:
            config_settings[operating_dir[0]] = operating_dir[1]

    # if encryption_mode in ('simple', 'standard'):
    keys_key = cipher.keys_key(config_settings['keys_key'])

    if encryption_mode == 'extreme':  # and keystore == 'Secrets.jks':
        extreme_key = cipher.keys_key(config_settings['extreme_key'])
        keys_key = cipher.decrypt_data(keys_key, extreme_key)

    keys_masterkey = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'masterkey')

    keytool = os.path.join(config_settings['keytool_dir'], 'keytool')
    try:
        # Keys.jks key
        keystore_key = keys_key

        if keystore == 'Secrets.jks':
            if encryption_mode == 'extreme':
                keys_masterkey = cipher.decrypt_data(keys_masterkey, extreme_key)
            keys_secrets = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'secrets')
            secrets_key = cipher.decrypt_data(keys_secrets, keys_masterkey)
            # Secrets.jks key
            keystore_key = secrets_key

        keystore_file = os.path.join(config_settings["secrets_dir"], keystore)
        subprocess.run(f'{keytool} -delete -alias {alias} -keystore {keystore_file} -storepass {keystore_key}', shell=True)
        subprocess.run(f'echo {value} | {keytool} ' +
                       f'-importpassword -keystore {keystore_file} ' +
                       f'-storepass {keystore_key} -alias {alias}',
                       input='yes\n', encoding='utf-8', shell=True)
        return True
    except Exception as e:
        print(e)
        return False


def validate_password(password):

    pattern_description = '''
Password must meet the following criteria:
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (!@#$%^&*(),.?"':{}|<>)
- Minimum length of 8 characters
'''

    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?"\':{}|<>]).{8,}$'
    if re.match(pattern, password):
        return True
    else:
        print(f"\nInvalid password. Please ensure it meets the criteria:{pattern_description}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Sec-Sci AutoPT Password Encryptor v1.0')
    parser.add_argument('-r', '--RandomKey', type=str,
                        help='Create random masterkey. Options: Y or N.')
    parser.add_argument('-pk', '--Passkey', type=str,
                        help='Enter password for masterkey.')
    parser.add_argument('-s', '--Salt', type=str,
                        help='Enter salt for masterkey.')
    parser.add_argument('-p', '--Password', type=str,
                        help='Enter password to encrypt.')
    parser.add_argument('-vp', '--ViewPassword', type=str,
                        default='n',
                        help='View password that was encrypted. Options: Y or N.')
    parser.add_argument('-kpf', '--KeepPasswordFile', type=str,
                        help='Keep "password.key" and "password.dat". Options: Y or N.')
    parser.add_argument('-smkamk2k', '--StoreMasterkeyAsMasterkey2Keys', type=str,
                        help='Import masterkey to "Keys.jks". Options: Y or N.')
    parser.add_argument('-sepas2k', '--StoreEncryptedPasswordAsSecrets2Keys', type=str,
                        help='Import encrypted password to "Keys.jks" as secrets. Options: Y or N. ')
    parser.add_argument('-sepamk2k', '--StoreEncryptedPasswordAsMasterkey2Keys', type=str,
                        help='Import encrypted password to "Keys.jks" as masterkey. Options: Y or N.')
    parser.add_argument('-sepamk2s', '--StoreEncryptedPasswordAsMasterkey2Secrets', type=str,
                        help='Import encrypted password to "Secrets.jks" as masterkey. Options: Y or N.')
    parser.add_argument('-sepagpgp', '--StoreEncryptedPasswordAsGPGPassword', type=str,
                        help='Import encrypted password to "Secrets.jks" as gpgpassphrase. Options: Y or N.')

    args = parser.parse_args()
    randomkey = str(args.RandomKey).lower()
    passkey = args.Passkey
    salt = args.Salt
    password_to_encrypt = args.Password
    check_encrypted_password = str(args.ViewPassword).lower()
    delete_key_password = str(args.KeepPasswordFile).lower()
    smkamk2k = args.StoreMasterkeyAsMasterkey2Keys
    sepas2k = args.StoreEncryptedPasswordAsSecrets2Keys
    sepamk2k = args.StoreEncryptedPasswordAsMasterkey2Keys
    sepamk2s = args.StoreEncryptedPasswordAsMasterkey2Secrets
    sepagpgp = args.StoreEncryptedPasswordAsGPGPassword

    if passkey:
        randomkey = 'n'

    while randomkey != 'n' and randomkey != 'y':
        randomkey = input("\nCreate random password key? [Y/n]: ").lower() or 'y'

    # if not args.randomkey:
    if randomkey == 'n':
        if not passkey:
            passkey = getpass.getpass(prompt='\nEnter password for masterkey: ')
        if not salt:
            salt = getpass.getpass(prompt='\nEnter salt for masterkey: ')
        masterkey = generate_key(passkey, salt.encode())
    else:
        masterkey = generate_random_key()

    # here
    save_key(masterkey)
    print(f'\nThis is the masterkey: {masterkey}')

    if not password_to_encrypt:
        password_to_encrypt = getpass.getpass(prompt='\nEnter password to encrypt: ')

    save_password(password_to_encrypt, masterkey)
    # to here

    # Read saved password
    encrypted_password = open('password.dat', 'rb').read()
    print(f'\nThis is the encrypted password: {encrypted_password}')

    while check_encrypted_password != 'n' and check_encrypted_password != 'y':
        check_encrypted_password = input('\nDo you want to see the password that was encrypted? [y/N]: ').lower() or 'n'

    # Retrieve the password
    if check_encrypted_password == 'y':
        retrieved_password = retrieve_password(open('password.key', 'rb').read())
        print(f'\nPassword that was encrypted: {retrieved_password}')

    while delete_key_password != 'n' and delete_key_password != 'y':
        delete_key_password = input("\npassword.key and password.dat files are created. " +
                                    "Do you want to keep it? [y/N]: ").lower() or 'n'

    if delete_key_password == 'n':
        try:
            if os.path.exists('password.key'): os.remove('password.key')
            if os.path.exists('password.dat'): os.remove('password.dat')
            print('\nDeleted: password.key and password.dat')
        except Exception as e:
            print(e)

    while smkamk2k != 'n' and smkamk2k != 'y':
        smkamk2k = input('\nImport masterkey to "Keys.jks"? [y/N]: ').lower() or 'n'

    if smkamk2k == 'y':
        imported = import_data_to_keystore('Keys.jks', 'masterkey', masterkey.decode())
        if imported:
            print('\nmasterkey imported to "Keys.jks"')

    while sepas2k != 'n' and sepas2k != 'y':
        sepas2k = input('\nImport encrypted password to "Keys.jks" as secrets? [y/N]: ').lower() or 'n'

    if sepas2k == 'y':
        imported = import_data_to_keystore('Keys.jks', 'secrets', encrypted_password.decode())
        if imported:
            print('\nsecrets imported to "Keys.jks"')

    while sepamk2k != 'n' and sepamk2k != 'y':
        sepamk2k = input('\nImport encrypted password to "Keys.jks" as masterkey? [y/N]: ').lower() or 'n'

    if sepamk2k == 'y':
        imported = import_data_to_keystore('Keys.jks', 'masterkey', encrypted_password.decode())
        if imported:
            print('\nmasterkey imported to "Keys.jks"')

    while sepamk2s != 'n' and sepamk2s != 'y':
        sepamk2s = input('\nImport encrypted password to "Secrets.jks" as masterkey? [y/N]: ').lower() or 'n'

    if sepamk2s == 'y':
        imported = import_data_to_keystore('Secrets.jks', 'masterkey', encrypted_password.decode())
        if imported:
            print('\nmasterkey imported to "Secrets.jks"')

    while sepagpgp != 'n' and sepagpgp != 'y':
        sepagpgp = input('\nImport encrypted password to "Secrets.jks" as gpgpassphrase? [y/N]: ').lower() or 'n'

    if sepagpgp == 'y':
        imported = import_data_to_keystore('Secrets.jks', 'gpgpassphrase', encrypted_password.decode())
        if imported:
            print('\ngpgpassphrase imported to "Secrets.jks"')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\nCancelled.')
        exit()
