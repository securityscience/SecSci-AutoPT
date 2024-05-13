# ---------------------------------------
# Sec-Sci AutoPT v4.2405 - January 2018
# ---------------------------------------
# Tool:      Setup Secrets v1.0
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2024 WWW.SECURITY-SCIENCE.COM


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import subprocess
import argparse
import getpass
import base64
import os
import re


def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(data.encode())
    return cipher_text


# Decrypt data using the key
def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data


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


def validate_password(password):
    if not password:
        return False
    pattern_description = ''' Password must meet the following criteria:
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (!@#$%^&*(),.?"':{}|<>)
- Minimum length of 8 characters'''

    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?"\':{}|<>]).{8,}$'
    if re.match(pattern, password):
        return True
    else:
        print(f"\nWeak password. {pattern_description}")
        return False


def import_secrets(secret_to_import, keystore, storepass, alias):
    keystore = os.path.join('Secrets', keystore)
    subprocess.run(f'echo {secret_to_import.decode()} | keytool -importpassword -keystore {keystore} ' +
                   f'-storepass {storepass} -alias {alias}', shell=True)


def password_match_check(password, input_text):
    confirm_password = ''
    while password != confirm_password:
        password = getpass.getpass(prompt=f'\nEnter {input_text}: ')
        while not validate_password(password):
            password = getpass.getpass(prompt=f'\nEnter {input_text}: ')
        while not confirm_password:
            confirm_password = getpass.getpass(prompt=f'\nRe-enter {input_text}: ')
        if password != confirm_password:
            confirm_password = ''
            print(f'\n{input_text} mismatch!')
    return password


def main():
    parser = argparse.ArgumentParser(description='Sec-Sci AutoPT Setup Secrets v1.0')
    parser.add_argument('-t', '--Type', type=str,
                        help='Encryption Type. [1] Simple; [2] Standard; [3] Extreme')

    parser.add_argument('-xk', '--ExtremeKey', type=str,
                        help='Enter Extreme key Password')
    parser.add_argument('-xks', '--ExtremeKeySalt', type=str,
                        help='Enter Extreme key Salt')

    parser.add_argument('-kk', '--KeysKey', type=str,
                        help='Enter Keys keystore key')

    parser.add_argument('-kmk', '--KeysMasterkey', type=str,
                        help='Enter Keys keystore Masterkey Password')
    parser.add_argument('-kmks', '--KeysMasterkeySalt', type=str,
                        help='Enter Keys keystore Masterkey Salt')

    parser.add_argument('-sk', '--SecretsKey', type=str,
                        help='Enter Secrets keystore key')

    parser.add_argument('-smk', '--SecretsMasterkey', type=str,
                        help='Enter Secrets keystore Masterkey Password')
    parser.add_argument('-smks', '--SecretsMasterkeySalt', type=str,
                        help='Enter Secrets keystore Masterkey Salt')

    parser.add_argument('-gpg', '--GPGPass', type=str,
                        help='Enter GNU Privacy Guard Passphrase')

    args = parser.parse_args()
    encryption_type = args.Type
    extreme_key_pass = args.ExtremeKey
    extreme_key_salt = args.ExtremeKeySalt
    keys_key = args.KeysKey
    keys_masterkey_pass = args.KeysMasterkey
    keys_masterkey_salt = args.KeysMasterkeySalt
    secrets_key = args.SecretsKey
    secrets_masterkey_pass = args.SecretsMasterkey
    secrets_masterkey_salt = args.SecretsMasterkeySalt
    gpg_passphrase = args.GPGPass

    while encryption_type not in ['1', '2', '3']:
        encryption_type = str(input("\nSelect Encryption Type. [1] Simple; [2] Standard; [3] Extreme: "))

    if encryption_type == '3':
        if not validate_password(extreme_key_pass):
            extreme_key_pass = password_match_check(extreme_key_pass, 'Extreme key Password')
        while not extreme_key_salt:
            extreme_key_salt = getpass.getpass(prompt='\nEnter Extreme key Salt: ')

    if encryption_type in ['1', '2', '3']:
        if not validate_password(keys_key):
            keys_key = password_match_check(keys_key, 'Keys keystore key')
        if not validate_password(keys_masterkey_pass):
            keys_masterkey_pass = password_match_check(keys_masterkey_pass, 'Keys keystore Masterkey Password')
        while not keys_masterkey_salt:
            keys_masterkey_salt = getpass.getpass(prompt='\nEnter Keys keystore Masterkey Salt: ')
        if not validate_password(secrets_key):
            secrets_key = password_match_check(secrets_key, 'Secrets keystore key')

    if encryption_type in ['2', '3']:
        if not validate_password(secrets_masterkey_pass):
            secrets_masterkey_pass = password_match_check(secrets_masterkey_pass, 'Secrets keystore Masterkey Password')
        while not secrets_masterkey_salt:
            secrets_masterkey_salt = getpass.getpass(prompt='\nEnter Secrets keystore Masterkey Salt: ')

    if encryption_type in ['1', '2', '3']:
        if not validate_password(gpg_passphrase):
            gpg_passphrase = password_match_check(gpg_passphrase, 'GNU Privacy Guard Passphrase')

    encryption_type_text = ('Simple', 'Standard', 'Extreme')[int(encryption_type) - 1]

    # Create Keys.jks
    keystore = os.path.join('Secrets', encryption_type_text + '_Keys.jks')
    if os.path.exists(keystore):
        keystore_overwrite = ''
        while keystore_overwrite not in ('n', 'y'):
            keystore_overwrite = input(f'\nSecrets\\{encryption_type_text}_Keys.jks and ' +
                                       f'Secrets\\{encryption_type_text}_Secrets.jks already exist. ' +
                                       'Do you like to overwrite? [y/N]: ').lower() or 'n'
        if keystore_overwrite.lower() == 'y':
            try:
                os.remove(os.path.join('Secrets', encryption_type_text + '_Keys.jks'))
                os.remove(os.path.join('Secrets', encryption_type_text + '_Secrets.jks'))
                os.remove(os.path.join('Secrets', encryption_type_text + '_Mode_Instructions.txt'))
            except Exception as e:
                print(f'\n{e}')
        else:
            exit()

    subprocess.run(f'keytool -genseckey -keyalg AES -keysize 128 -alias myalias ' +
                   f'-keystore {keystore} -storepass {keys_key}', shell=True)

    # Create Secrets.jks
    keystore = os.path.join('Secrets', encryption_type_text + '_Secrets.jks')
    subprocess.run(f'keytool -genseckey -keyalg AES -keysize 128 -alias myalias ' +
                   f'-keystore {keystore} -storepass {secrets_key}', shell=True)

    # Import Secrets
    secrets_details_keys_key = f'Keys Key: {keys_key}'

    if encryption_type == '1':
        keys_masterkey = generate_key(keys_masterkey_pass, keys_masterkey_salt.encode())
        keys_secrets_encrypted = encrypt_data(secrets_key, keys_masterkey)
        secrets_gpgpassphrase_encrypted = encrypt_data(gpg_passphrase, keys_masterkey)
        secrets_details_masterkey = keys_masterkey_pass
        secrets_details_masterkey_salt = keys_masterkey_salt

        import_secrets(keys_masterkey, f'{encryption_type_text}_Keys.jks', keys_key, 'masterkey')
        import_secrets(keys_secrets_encrypted, f'{encryption_type_text}_Keys.jks', keys_key, 'secrets')
        import_secrets(secrets_gpgpassphrase_encrypted, f'{encryption_type_text}_Secrets.jks', secrets_key, 'gpgpassphrase')
    elif encryption_type in ['2', '3']:
        keys_masterkey = generate_key(keys_masterkey_pass, keys_masterkey_salt.encode())
        if encryption_type == '3':
            extreme_key = generate_key(extreme_key_pass, extreme_key_salt.encode())
            keys_masterkey_encrypted = encrypt_data(keys_masterkey.decode(), extreme_key)
        keys_secrets_encrypted = encrypt_data(secrets_key, keys_masterkey)

        secrets_masterkey = generate_key(secrets_masterkey_pass, secrets_masterkey_salt.encode())
        secrets_masterkey_encrypted = encrypt_data(secrets_masterkey.decode(), keys_masterkey)
        secrets_gpgpassphrase_encrypted = encrypt_data(gpg_passphrase, secrets_masterkey)
        secrets_details_masterkey = secrets_masterkey_pass
        secrets_details_masterkey_salt = secrets_masterkey_salt

        if encryption_type == '3':
            keys_masterkey = keys_masterkey_encrypted
            keys_key_encrypted = encrypt_data(keys_key, extreme_key)
            secrets_details_keys_key = f'Extreme Key: {extreme_key.decode()}\n   Encrypted Keys Key: {keys_key_encrypted.decode()}'

        import_secrets(keys_masterkey, f'{encryption_type_text}_Keys.jks', keys_key, 'masterkey')
        import_secrets(keys_secrets_encrypted, f'{encryption_type_text}_Keys.jks', keys_key, 'secrets')
        import_secrets(secrets_masterkey_encrypted, f'{encryption_type_text}_Secrets.jks', secrets_key, 'masterkey')
        import_secrets(secrets_gpgpassphrase_encrypted, f'{encryption_type_text}_Secrets.jks', secrets_key, 'gpgpassphrase')

    secrets_details = (f'Instructions to setup Secrets for {encryption_type_text} mode encryption:\n\n' +
                       f'1) Rename {encryption_type_text}_Keys.jks to Keys.jks\n\n' +
                       f'2) Rename {encryption_type_text}_Secrets.jks to Secrets.jks\n\n' +
                       f'3) Use the following keys and put on Windows Credential Manager or KeyRing or ENV Variable or Filesystem or Windows Registry\n\n' +
                       f'   {secrets_details_keys_key}\n\n' +
                       f'4) Use the following command to encrypt passwords and API keys:\n\n' +
                       f'   python password_encryptor.py -pk {secrets_details_masterkey} -s {secrets_details_masterkey_salt} -p <PASSWORD_TO_ENCRYPT>\n\n' +
                       'Warning! Please keep this file confidential and/or store it in a safe place.')

    # Write Details To A File
    with open(os.path.join('Secrets', f'{encryption_type_text}_Mode_Instructions.txt'), 'wb') as secrets_file:
        secrets_file.write(secrets_details.encode())

    print('\nOpen ' + os.path.join('Secrets', f'{encryption_type_text}_Mode_Instructions.txt') + ' and follow the instructions.')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\nCancelled.')
        exit()
