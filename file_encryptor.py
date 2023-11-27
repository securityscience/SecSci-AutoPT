# ---------------------------------------
# Sec-Sci AutoPT v3.2311 - January 2018
# ---------------------------------------
# Tool:      File Encryptor v2.0
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM

import cipher
import argparse
import configparser
import glob
import os


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


def file_encrypt(folders, gpg_dir, passphrase):
    files = []
    for folder in folders:
        folder = rf'{str(folder).strip()}'
        for file_extension in ['.json', '.env', '.crt', '.pfx', '.p12']:
            pattern = glob.glob(os.path.join(folder, f'*{file_extension}'))
            for file in pattern:
                if os.path.exists(file):
                    files.append(file)

    for encrypt_file in files:
        encrypted = cipher.encrypt_file(gpg_dir, encrypt_file, f'{encrypt_file}.gpg', passphrase)
        if encrypted:
            print(f'Encrypted: {encrypt_file}.gpg')
            os.remove(encrypt_file)


def file_decrypt(folders, gpg_dir, passphrase):
    files = []
    for folder in folders:
        folder = rf'{str(folder).strip()}'
        pattern = glob.glob(os.path.join(folder, f'*gpg'))
        for file in pattern:
            if os.path.exists(file):
                files.append(file)

    for decrypt_file in files:
        decrypted = cipher.decrypt_file(gpg_dir, f'{decrypt_file}', f'{decrypt_file[:-4]}', passphrase)
        if decrypted:
            print(f'Decrypted: {decrypt_file[:-4]}')
            os.remove(decrypt_file)
        else:
            print(f'Decryption failed for "{decrypt_file}". Invalid decryption password.')


def main():
    config_settings = initialize_config('autopt.conf')

    if not config_settings:
        print('Config Settings Initialization Error...')
        exit()

    for operating_dir in [('repo_dir', os.path.join(os.getcwd(), 'Repo')),
                          ('secrets_dir', os.path.join(os.getcwd(), 'Secrets'))]:

        if not config_settings[operating_dir[0].strip()]:
            config_settings[operating_dir[0]] = operating_dir[1]

    encryption_mode = str(config_settings['encryption_mode']).lower()
    java_dir = config_settings['java_dir']
    repo_dir = config_settings['repo_dir']
    secrets_dir = config_settings['secrets_dir']
    gpg_dir = config_settings['gpg_dir']
    passphrase = ''

    parser = argparse.ArgumentParser(description='Sec-Sci AutoPT File Encryptor v1.0')
    parser.add_argument('-a', '--action', type=str,
                        help='Options: encrypt or decrypt')
    parser.add_argument('-f', '--folder', type=str,
                        default=f'{repo_dir}, {secrets_dir}',
                        help=f'Enter folder path to encrypt or decrypt. Default value is {repo_dir}, {secrets_dir}')

    args = parser.parse_args()
    action = str(args.action).lower()
    folders = str(args.folder).split(',')
    keys_key = cipher.keys_key(config_settings['keys_key'])

    if encryption_mode == 'simple':
        keys_masterkey = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'masterkey')
        keys_secrets = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'secrets')
        secrets_key = cipher.decrypt_data(keys_secrets, keys_masterkey)
        gpgpassphrase = cipher.get_key(java_dir, secrets_dir, 'Secrets.jks', secrets_key, 'gpgpassphrase')
        passphrase = cipher.decrypt_data(gpgpassphrase, keys_masterkey)
    elif encryption_mode == 'standard':
        keys_masterkey = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'masterkey')
        keys_secrets = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'secrets')
        secrets_key = cipher.decrypt_data(keys_secrets, keys_masterkey)
        secrets_masterkey = cipher.get_key(java_dir, secrets_dir, 'Secrets.jks', secrets_key, 'masterkey')
        masterkey = cipher.decrypt_data(secrets_masterkey, keys_masterkey)
        gpgpassphrase = cipher.get_key(java_dir, secrets_dir, 'Secrets.jks', secrets_key, 'gpgpassphrase')
        passphrase = cipher.decrypt_data(gpgpassphrase, masterkey)
    elif encryption_mode == 'extreme':
        extreme_key = cipher.keys_key(config_settings['extreme_key'])
        keys_key = cipher.decrypt_data(keys_key, extreme_key)
        keys_masterkey = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'masterkey')
        keys_masterkey = cipher.decrypt_data(keys_masterkey, extreme_key)
        keys_secrets = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'secrets')
        secrets_key = cipher.decrypt_data(keys_secrets, keys_masterkey)
        secrets_masterkey = cipher.get_key(java_dir, secrets_dir, 'Secrets.jks', secrets_key, 'masterkey')
        masterkey = cipher.decrypt_data(secrets_masterkey, keys_masterkey)
        gpgpassphrase = cipher.get_key(java_dir, secrets_dir, 'Secrets.jks', secrets_key, 'gpgpassphrase')
        passphrase = cipher.decrypt_data(gpgpassphrase, masterkey)

    if action == 'encrypt':
        file_encrypt(folders, gpg_dir, passphrase)
    elif action == 'decrypt':
        file_decrypt(folders, gpg_dir, passphrase)
    else:
        print(f'Invalid --action {action}')


if __name__ == "__main__":
    main()
