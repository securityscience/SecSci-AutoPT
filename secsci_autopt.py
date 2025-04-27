# ---------------------------------------
# Sec-Sci AutoPT v5.240704 - July 2024
# ---------------------------------------
# Tool:      Sec-Sci AutoPT v5.240704
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM

# pip install docker
# pip install sendgrid
# pip install psutil

from email.mime.multipart import MIMEMultipart
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from email.mime.text import MIMEText
from datetime import datetime
import configparser
import subprocess
import zipfile
import tarfile
import smtplib
import shutil
import psutil
import docker
import cipher
import gzip
import time
import glob
import os


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


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


def docker_status():
    try:
        check_docker = docker.from_env()
        check_docker.ping()
        return True
    except docker.errors.DockerException:
        return False


def check_new_job(job_dir, repo_dir, burp_templates_dir, ws_dir, reports_dir, encrypt_all_creds,
                  java_dir, secrets_dir, keys_key, gpg_dir, masterkey, passphrase,
                  proxy_host, proxy_port, use_app_burp_file):
    job_file = os.path.join(job_dir, '*.job')

    new_jobs = glob.glob(job_file)

    if new_jobs:
        new_job = min(new_jobs, key=os.path.getmtime)

        # Get the oldest job
        if not prepare_job(new_job, repo_dir, burp_templates_dir, ws_dir, reports_dir, encrypt_all_creds,
                           secrets_dir, gpg_dir, masterkey, passphrase, proxy_host, proxy_port, use_app_burp_file):

            return
        return new_job
    else:
        return


def prepare_job(new_job, repo_dir, burp_templates_dir, ws_dir, reports_dir, encrypt_all_creds,
                secrets_dir, gpg_dir, masterkey, passphrase, proxy_host, proxy_port, use_app_burp_file):
    encrypt_all_creds = str(encrypt_all_creds).lower()
    # Encrypt or Decrypt Files or Do Nothing
    process_encryption_mode(encrypt_all_creds)
    job_file = os.path.basename(new_job)
    project_name = str(job_file).split('.')[0]
    job_type = project_name[-3:]

    project_settings_files = glob.glob(os.path.join(repo_dir, f'{project_name}.*'))

    if not project_settings_files:
        print('No Project Settings Available...')
        os.rename(new_job, f'{new_job}-ns')
        return False

    cleanup_job(project_name, ws_dir)

    burp_template = os.path.join(burp_templates_dir, 'SecSciAutoPTScan.burp')
    burp_project = f'{os.path.join(ws_dir, project_name)}.burp'
    shutil.move(new_job, ws_dir)

    for project_setting in project_settings_files:
        shutil.copy(project_setting, ws_dir)

    project_settings = initialize_config(f'{os.path.join(ws_dir, project_name)}.settings')

    # Use application previous scan Burp file: Yes or No
    if 'use_app_burp_file' in project_settings:
        use_app_burp_file = str(project_settings['use_app_burp_file']).lower()

    # Check Report Dir for Existing Burp File
    reports_burp_file = ''
    if use_app_burp_file == 'yes':
        reports_burp_file = glob.glob(os.path.join(reports_dir, f'{project_name}*.burp'))

    if reports_burp_file and use_app_burp_file == 'yes':
        # Use Application Previous Scan Burp File
        shutil.copy(reports_burp_file[0], burp_project)
    else:
        shutil.copy(burp_template, burp_project)

    if job_type == 'dkr':
        gpg_extension = ''

        if encrypt_all_creds == 'on':
            gpg_extension = '.gpg'

        docker_app_credential = project_settings['docker_app_credential'] + gpg_extension
        docker_app_crt = project_settings['docker_app_crt'] + gpg_extension
        docker_app_pfx = project_settings['docker_app_pfx'] + gpg_extension

        # Rename docker_app_credential, docker_app_crt, docker_app_pfx if found
        for app_cert_credential in (docker_app_credential, docker_app_crt, docker_app_pfx):
            app_cert_credential_base_file = os.path.join(ws_dir, f'{project_name}.{app_cert_credential}')
            app_cert_credential_file = os.path.join(ws_dir, app_cert_credential)
            if os.path.exists(app_cert_credential_base_file):
                if os.path.exists(app_cert_credential_file):
                    os.remove(app_cert_credential_file)
                os.rename(app_cert_credential_base_file, app_cert_credential_file)

    burp_certificate_password = project_settings['burp_certificate_password']
    # Decrypt Certificate
    burp_certificate = str(project_settings['burp_certificate']).strip()
    if burp_certificate:
        if burp_certificate and encrypt_all_creds == 'on':
            cipher.decrypt_file(gpg_dir,
                                f'{os.path.join(secrets_dir, project_settings["burp_certificate"])}.gpg',
                                f'{os.path.join(ws_dir, project_settings["burp_certificate"])}',
                                passphrase)
        else:
            try:
                shutil.copy(f'{os.path.join(secrets_dir, project_settings["burp_certificate"])}',
                            f'{os.path.join(ws_dir, project_settings["burp_certificate"])}')
            except FileNotFoundError as e:
                print(e)
                cleanup_job(project_name, ws_dir)
                return False

        if encrypt_all_creds == 'on':
            burp_certificate_password = cipher.decrypt_data(burp_certificate_password, masterkey)
            encrypted_files = glob.glob(os.path.join(ws_dir, '*.gpg'))

            for encrypted_file in encrypted_files:
                decrypted_file = os.path.basename(encrypted_file)
                cipher.decrypt_file(gpg_dir, encrypted_file, os.path.join(ws_dir, decrypted_file[:-4]), passphrase)

    try:
        shutil.copy(os.path.join(burp_templates_dir, project_settings['burp_template']),
                    f'{os.path.join(ws_dir, project_name)}.burpoptions')
    except Exception as e:
        print(e)
        exit()

    # Set BurpOptions Variables
    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{proxy_host}', proxy_host)

    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{proxy_port}', proxy_port)

    if os.name == 'nt':
        certificate_file = str(os.path.join(ws_dir, burp_certificate)).replace('\\', '\\\\')
    else:
        certificate_file = os.path.join(ws_dir, burp_certificate)

    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{certificate_file}', certificate_file)

    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{certificate_password}', burp_certificate_password)

    tls_pass_through = ''

    if 'tls_pass_through_host' in project_settings:
        tls_pass_through_hosts = str(project_settings['tls_pass_through_host']).replace('.','\\\\.').split(',')

        if tls_pass_through_hosts[0]:
            tls_pass_through_objects = [f'{{"enabled":true,"file":"^/.*","host":"^{tls_pass_through_host.strip()}$","protocol":"any"}}'
                                        for tls_pass_through_host in tls_pass_through_hosts]
            tls_pass_through = ','.join(tls_pass_through_objects)

    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{tls_pass_through_hosts}', tls_pass_through)

    inc_urls = ''

    if 'include_url' in project_settings:
        include_urls = str(project_settings['include_url']).split(',')

        if include_urls[0]:
            include_objects = [f'{{"enabled":true,"include_subdomains":false,"prefix":"{include_url.strip()}"}}'
                               for include_url in include_urls]
            inc_urls = ','.join(include_objects)

    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{include_urls}', inc_urls)

    exc_urls = ''

    if 'exclude_url' in project_settings:
        exclude_urls = str(project_settings['exclude_url']).split(',')

        if exclude_urls[0]:
            exclude_objects = [f'{{"enabled":true,"include_subdomains":false,"prefix":"{exclude_url}"}}' for exclude_url in exclude_urls]
            exc_urls = ','.join(exclude_objects)

    set_burp_settings(os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      os.path.join(ws_dir, f'{project_name}.burpoptions'),
                      '{exclude_urls}', exc_urls)
    return True


def set_burp_settings(input_file, outputfile, current_string, new_string):

    try:
        with open(input_file, 'r') as file:
            file_content = file.read()

        updated_content = file_content.replace(current_string, new_string)

        with open(outputfile, 'w') as file:
            file.write(updated_content)

    except Exception as e:
        print(e)


def cleanup_job(project_name, ws_dir, reports_dir='', burp_report_datetime='', success_scan=False):
    print('\nCleaning Up Workspace...')
    project_name = str(project_name).split('.')[0]

    if success_scan:
        # Archive Old Reports
        reports_to_archive = glob.glob(os.path.join(reports_dir, f'{project_name}*'))
        archived_dir = os.path.join(reports_dir, 'Archived')
        for report_to_archive in reports_to_archive:
            if os.path.exists(report_to_archive):
                try:
                    shutil.move(report_to_archive, archived_dir)
                except Exception:
                    pass

        # Copy PenTest Reports to Reports
        for report_ext in ['.html', '.xml', '.burp']:
            exported_report_file = os.path.join(ws_dir, f'{project_name}{report_ext}')
            final_report_file = os.path.join(reports_dir, f'{project_name}_{burp_report_datetime}{report_ext}')
            if os.path.exists(exported_report_file):
                shutil.copy(exported_report_file, final_report_file)

    shutil.rmtree(ws_dir, ignore_errors=True)
    try:
        os.mkdir(ws_dir)
    except Exception as e:
        print(e)


def gcr_account_activation(service_account, service_account_key):
    # GCR Authentication to download images from the image repository
    print(f'\nActivating GCR Service Account {service_account}')
    account_activation = subprocess.run(f'gcloud auth activate-service-account {service_account} ' +
                                        f'--key-file {service_account_key}', shell=True)

    if account_activation.returncode != 0:
        return False
    return True


def jfr_account_activation(service_account, service_account_key, jfr_server):
    # JFrog Authentication to download images from the image repository
    print(f'\nActivating JFrog Service Account {service_account}')
    account_activation = subprocess.run(f'docker login -u {service_account} ' +
                                        f'--password-stdin <  {service_account_key} {jfr_server}', shell=True)

    if account_activation.returncode != 0:
        return False
    return True


def prepare_docker(project_name, image_url):
    print('\nPreparing Docker Image...')
    print(f'\nCleaning Up {project_name} Docker Container.')

    try:
        container = docker.from_env().containers.get(project_name)
        container.stop()
        container.remove()
    except docker.errors.NotFound:
        print(f'\nContainer {project_name} not found.')

    image_url_tag = str(image_url.split(':')[1]).lower().strip()

    if image_url_tag != 'local':
        # Pulling Docker image from the image repository
        print(f'\nPulling Docker Image For {project_name}')
        docker_pull = subprocess.run(f'docker pull {image_url}', shell=True)
        if docker_pull.returncode != 0:
            # Send Email: Docker Pull Error
            return False
    return True


def run_container(project_name, ws_dir, docker_volume, docker_entrypoint, image_name, docker_entrypoint_script):
    env_file = os.path.join(ws_dir, f'{project_name}.env')
    container_volume = f'{str(docker_volume).replace("WSDir", ws_dir)}'

    docker_run = subprocess.run(f'docker run --name {project_name} --env-file {env_file} {container_volume} ' +
                                f'{docker_entrypoint} {image_name} {docker_entrypoint_script}', shell=True)

    return docker_run.returncode


def sendgrid_mail(api_key, email_from, email_to, subject, message):
    to_emails = []
    for email in email_to:
        to_emails.append(email)

    sg = SendGridAPIClient(api_key)
    mail_message = Mail(
        from_email=email_from,
        to_emails=to_emails,
        subject=subject,
        html_content=message
    )

    try:
        mail_response = sg.send(mail_message)
        print(f'\nSendgrid email sent with status code: {mail_response.status_code}')
        return True
    except Exception as e:
        print(f'\nError sending email: {str(e)}')
        return False


def smtp_mail(smtp_server, smtp_port, smtp_username, smtp_password, email_from, email_to, subject, message):
    the_message = MIMEMultipart('alternative')
    the_message.attach(MIMEText(message, 'html'))

    try:
        # Start the SMTP Connection and Login
        mail_server = smtplib.SMTP(smtp_server, smtp_port)
        mail_server.starttls()
        mail_server.login(smtp_username, smtp_password)

        # Compose the email
        the_message["From"] = email_from
        the_message["To"] = ", ".join(email_to)
        the_message["Subject"] = subject

        mail_server.sendmail(email_from, email_to, the_message.as_string())

        mail_server.quit()

        print('Email sent successfully.')
    except Exception as e:
        print(e)


def send_email(config_settings, email_to, subject, message, masterkey):
    print(email_to)
    mailer = str(config_settings['mailer']).lower()
    encrypt_all_creds = str(config_settings['encrypt_all_creds']).lower()
    sendgrid_api_key = config_settings['sendgrid_api_key']
    smtp_password = config_settings['smtp_password']

    if encrypt_all_creds == 'on':
        """the_masterkey = cipher.masterkey(config_settings['java_dir'],
                                         config_settings['secrets_dir'],
                                         config_settings['keys_key'])"""
        if mailer == 'sendgrid':
            sendgrid_api_key = cipher.decrypt_data(config_settings['sendgrid_api_key'],
                                                   masterkey)

        elif mailer == 'smtp':
            smtp_password = cipher.decrypt_data(config_settings['smtp_password'],
                                                masterkey)
        if not smtp_password or not sendgrid_api_key:
            cleanup_job('Clear', config_settings['ws_dir'])
            print('\nDecryption Error: Please check smtp_password or sendgrid_api_key encrypted data...')
            exit()

    if mailer == 'sendgrid':
        sendgrid_mail(sendgrid_api_key,
                      config_settings['email_sender'],
                      email_to,
                      subject,
                      message)
    elif mailer == 'smtp':
        smtp_mail(config_settings['smtp_server'],
                  config_settings['smtp_port'],
                  config_settings['smtp_username'],
                  smtp_password,
                  config_settings['email_sender'],
                  email_to,
                  subject,
                  message)


def run_burpsuite(java_dir, burp_dir, burp_temp_dir, ws_dir, project_name):
    # Delete Burp Temp Files
    if os.path.exists(burp_temp_dir) and os.path.isdir(burp_temp_dir):
        shutil.rmtree(burp_temp_dir, ignore_errors=True)
        os.makedirs(burp_temp_dir, exist_ok=True)

    java = os.path.join(java_dir, 'java')
    burp_jar = os.path.join(burp_dir, 'burpsuite_pro.jar')
    burp_project = os.path.join(ws_dir, f'{project_name}.burp')
    burp_config = os.path.join(ws_dir, f'{project_name}.burpoptions')

    print('\nRunning Burpsuite Pro...')
    burp = subprocess.Popen(f'{java} --illegal-access=permit -jar {burp_jar} ' +
                            f'--xBurp --project-file={burp_project} ' +
                            f'--config-file={burp_config} --auto-repair ' +
                            '--unpause-spider-and-scanner --disable-auto-update', shell=True)

    time.sleep(11)
    return burp.pid


def export_report(java_dir, burp_dir, ws_dir, project_name, burp_report_format):
    java = os.path.join(java_dir, 'java')
    burp_jar = os.path.join(burp_dir, 'burpsuite_pro.jar')
    burp_report_filename = os.path.join(ws_dir, project_name)
    burp_project = os.path.join(ws_dir, f'{project_name}.burp')

    print('\nExporting PenTest Report...')
    burp = subprocess.run(f'{java} --illegal-access=permit -Djava.awt.headless=true ' +
                          f'-jar {burp_jar} --xReport {burp_report_format} ' +
                          f'{burp_report_filename} --project-file={burp_project} ' +
                          '--auto-repair --disable-auto-update', shell=True)
    return burp.returncode


def get_child_process_ids(pid):
    try:
        parent_process = psutil.Process(pid)
        child_processes = parent_process.children(recursive=True)
        return [child.pid for child in child_processes]
    except psutil.NoSuchProcess:
        print(f'\nProcess ID: {pid} not found.')
        return []


def is_process_id_running(pid):
    return psutil.pid_exists(pid)


def terminate_process_id(pid):
    # Reserved For Testing
    try:
        terminate_process = psutil.Process(pid)
        for burp in terminate_process.children(recursive=True):
            burp.kill()
        terminate_process.kill()
        return True
    except psutil.NoSuchProcess:
        print(f'\nProcess ID: {pid} not found.')
        return False


def uncompressed_file(compressed_file, extract_to_folder):
    print(f'\nExtracting {compressed_file}...')
    try:
        if compressed_file.endswith('.zip'):
            with zipfile.ZipFile(compressed_file, 'r') as zip_ref:
                zip_ref.extractall(extract_to_folder)
            print(f'\nUnzipped {compressed_file} to {extract_to_folder}')
        elif compressed_file.endswith('.tar'):
            with tarfile.open(compressed_file, 'r') as tar_ref:
                tar_ref.extractall(extract_to_folder)
            print(f'\nUntarred {compressed_file} to {extract_to_folder}')
        elif compressed_file.endswith('.tar.gz') or compressed_file.endswith('.tgz'):
            with tarfile.open(compressed_file, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to_folder)
            print(f'\nUntarred {compressed_file} to {extract_to_folder}')
        elif compressed_file.endswith('.gz'):
            with gzip.open(compressed_file, 'rb') as gz_ref:
                extract_path = os.path.join(extract_to_folder, os.path.basename(compressed_file)[:-3])
                with open(extract_path, 'wb') as out_file:
                    out_file.write(gz_ref.read())
            print(f'\nUngzipped {compressed_file} to {extract_path}')
        else:
            print(f'\nUnsupported compression format for {compressed_file}')
            return False
        return True

    except Exception as e:
        print(f'\nError during extraction: {e}')
        return False


def docker_job(new_job, config_settings, masterkey, passphrase):
    job_name = os.path.split(new_job)[-1]
    project_name = job_name.split('.')[0]
    before_down_time = datetime.now()
    first_email_notice = False
    reports_dir = config_settings['reports_dir']
    ws_dir = config_settings['ws_dir']
    secrets_dir = config_settings['secrets_dir']
    encrypt_all_creds = str(config_settings['encrypt_all_creds']).lower()
    gpg_dir = config_settings['gpg_dir']

    while not docker_status():
        email_to = config_settings['admin_email']

        # Send first email notification if docker service is down
        if not first_email_notice:
            docker_service_error_subject = config_settings['docker_service_error_subject']
            docker_service_error_message = config_settings['docker_service_error_message']

            send_email(config_settings, email_to,
                       docker_service_error_subject,
                       docker_service_error_message,
                       masterkey)
            print("email")
            exit()

            first_email_notice = True

        down_time_hr = ((datetime.now() - before_down_time).total_seconds() / 60) / 60
        cls()
        print('Docker is down...')

        # Send another email notification after the set intervals in hours
        if down_time_hr >= config_settings['docker_service_notice_interval']:
            docker_service_error_subject = config_settings['docker_service_error_subject']
            docker_service_error_message = config_settings['docker_service_error_message']

            send_email(config_settings, email_to,
                       docker_service_error_subject,
                       docker_service_error_message,
                       masterkey)

            before_down_time = datetime.now()

        time.sleep(10)

    job_file = os.path.join(ws_dir, job_name)
    with open(job_file, 'r') as file:
        image_url = file.read()

    project_settings = initialize_config(os.path.join(ws_dir, f'{project_name}.settings'))
    email_to = project_settings['email_to']
    repository_type = str(project_settings['repository_type']).lower()
    image_pull_account_activated = False
    pull_account = ''

    if repository_type == 'gcr':
        gcr_service_account = project_settings['gcr_service_account']
        if encrypt_all_creds == 'on':
            # Decrypt GCR Service Account Key
            cipher.decrypt_file(gpg_dir,
                                f'{os.path.join(secrets_dir, project_settings["gcr_service_account_key"])}.gpg',
                                f'{os.path.join(ws_dir, project_settings["gcr_service_account_key"])}',
                                passphrase)
        else:
            try:
                shutil.copy(f'{os.path.join(secrets_dir, project_settings["gcr_service_account_key"])}',
                            f'{os.path.join(ws_dir, project_settings["gcr_service_account_key"])}')
            except FileNotFoundError as e:
                print(e)
                cleanup_job(project_name, ws_dir)
                return

        gcr_service_account_key = os.path.join(ws_dir, f'{project_settings["gcr_service_account_key"]}')
        pull_account = gcr_service_account
        image_pull_account_activated = gcr_account_activation(gcr_service_account, gcr_service_account_key)

    elif repository_type == 'jfr':
        jfr_service_account = project_settings["jfr_service_account"]
        if encrypt_all_creds == 'on':
            # Decrypt GCR Service Account Key
            cipher.decrypt_file(gpg_dir,
                                f'{os.path.join(secrets_dir, project_settings["jfr_service_account_key"])}.gpg',
                                f'{os.path.join(ws_dir, project_settings["jfr_service_account_key"])}',
                                passphrase)
        else:
            try:
                shutil.copy(f'{os.path.join(secrets_dir, project_settings["jfr_service_account_key"])}',
                            f'{os.path.join(ws_dir, project_settings["jfr_service_account_key"])}')
            except FileNotFoundError as e:
                print(e)
                cleanup_job(project_name, ws_dir)
                return

        jfr_service_account_key = os.path.join(ws_dir, f'{project_settings["jfr_service_account_key"]}')
        jfr_server = project_settings["jfr_server"]
        pull_account = jfr_service_account
        image_pull_account_activated = jfr_account_activation(jfr_service_account, jfr_service_account_key, jfr_server)

    elif repository_type == 'local':
        # Skip Pull Account Activation for imported image
        image_pull_account_activated = True

    if not image_pull_account_activated:
        image_pull_account_activation_error_subject = (
            str(config_settings['image_pull_account_activation_error_subject']))
        image_pull_account_activation_error_subject = (
            image_pull_account_activation_error_subject.replace('{project_name}', project_name[0:-4]))
        image_pull_account_activation_error_message = (
            str(config_settings['image_pull_account_activation_error_message']))
        image_pull_account_activation_error_message = (
            image_pull_account_activation_error_message.replace('{project_name}', project_name[0:-4]))
        image_pull_account_activation_error_message = (
            image_pull_account_activation_error_message.replace('{pull_account}', pull_account))

        send_email(config_settings, email_to,
                   image_pull_account_activation_error_subject,
                   image_pull_account_activation_error_message,
                   masterkey)

        cleanup_job(project_name, ws_dir)
        return

    project_docker = prepare_docker(project_name, image_url)

    # Send email if Docker Pull is failed
    if not project_docker:
        pull_error_subject = str(config_settings['docker_pull_error_subject'])
        pull_error_subject = pull_error_subject.replace('{project_name}', project_name[0:-4])
        pull_error_message = str(config_settings['docker_pull_error_message'])
        pull_error_message = pull_error_message.replace('{project_name}', project_name[0:-4])
        pull_error_message = pull_error_message.replace('{image_name}', image_url)

        send_email(config_settings, email_to,
                   pull_error_subject,
                   pull_error_message,
                   masterkey)

        cleanup_job(project_name, ws_dir)
        return

    burp_pid = run_burpsuite(config_settings['java_dir'], config_settings['burp_dir'],
                             config_settings['burp_temp_dir'], config_settings['ws_dir'], project_name)

    burp_child_pid = get_child_process_ids(burp_pid)[0]

    is_container_running = False
    while is_process_id_running(burp_child_pid):
        if not is_container_running:
            container_status = run_container(project_name, ws_dir, project_settings['docker_volume'],
                                             project_settings['docker_entrypoint'],
                                             image_url, project_settings['docker_entrypoint_script'])

            if container_status != 0:
                print('\nContainer run completed but encountered some issues.')
            else:
                print('\nContainer run completed.')

            print('\nPenetrating testing in progress...\n')

            is_container_running = True

        time.sleep(3)

    terminate_process_id(burp_pid)

    print('\nBurp scan completed...')

    xreport = export_report(config_settings['java_dir'], config_settings['burp_dir'], ws_dir,
                            project_name, config_settings['burp_report_format'])

    if xreport != 0:
        print('\nPenTest Report Exported.')

    burp_report_datetime = datetime.now().strftime('%Y-%m-%d@%H.%M.%S')
    cleanup_job(project_name, ws_dir, reports_dir, burp_report_datetime, True)

    # Send Successful Scan Message
    report_url = f'{config_settings["report_url"]}{project_name}'
    success_scan_subject = str(config_settings['success_scan_subject'])
    success_scan_subject = success_scan_subject.replace('{project_name}', project_name[0:-4])
    success_scan_message = str(config_settings['success_scan_message'])
    success_scan_message = success_scan_message.replace('{project_name}', project_name[0:-4])
    success_scan_message = success_scan_message.replace('{report_url}', report_url)

    send_email(config_settings, email_to,
               success_scan_subject,
               success_scan_message,
               masterkey)


def cucumber_job(new_job, config_settings, masterkey):
    job_name = os.path.split(new_job)[-1]
    project_name = job_name.split('.')[0]
    reports_dir = config_settings['reports_dir']
    ws_dir = config_settings['ws_dir']

    project_settings = initialize_config(os.path.join(ws_dir, f'{project_name}.settings'))

    email_to = project_settings['email_to']

    burp_pid = run_burpsuite(config_settings['java_dir'], config_settings['burp_dir'],
                             config_settings['burp_temp_dir'], config_settings['ws_dir'], project_name)

    burp_child_pid = get_child_process_ids(burp_pid)[0]

    java = os.path.join(project_settings['java_dir'], 'java')
    project_jar = os.path.join(ws_dir, f'{project_name}.jar')
    is_cucumber_running = False
    while is_process_id_running(burp_child_pid):
        if not is_cucumber_running:
            print(f'\nRunning Cucumber for {project_name}')
            root_dir = os.getcwd()
            os.chdir(ws_dir)
            cucumber_status = subprocess.run(f'{java} ' +
                                             f'-Dhttps.proxyHost={config_settings["proxy_host"]} ' +
                                             f'-Dhttps.proxyPort={config_settings["proxy_port"]} ' +
                                             f'{project_settings["java_option"]} -jar {project_jar}', shell=True)
            os.chdir(root_dir)

            if cucumber_status.returncode != 0:
                print('\nCucumber execution completed but encountered some issues.')
            else:
                print('\nCucumber execution completed.')

            print('\nPenetrating testing in progress...\n')

            is_cucumber_running = True

        time.sleep(3)

    terminate_process_id(burp_pid)

    print('\nBurp scan completed...')

    xreport = export_report(config_settings['java_dir'], config_settings['burp_dir'], ws_dir,
                            project_name, config_settings['burp_report_format'])

    if xreport != 0:
        print('\nPenTest Report Exported.')

    burp_report_datetime = datetime.now().strftime('%Y-%m-%d@%H.%M.%S')
    cleanup_job(project_name, ws_dir, reports_dir, burp_report_datetime, True)

    # Send Successful Scan Message
    report_url = f'{config_settings["report_url"]}{project_name}'
    success_scan_subject = str(config_settings['success_scan_subject'])
    success_scan_subject = success_scan_subject.replace('{project_name}', project_name[0:-4])
    success_scan_message = str(config_settings['success_scan_message'])
    success_scan_message = success_scan_message.replace('{project_name}', project_name[0:-4])
    success_scan_message = success_scan_message.replace('{report_url}', report_url)

    send_email(config_settings, email_to,
               success_scan_subject,
               success_scan_message,
               masterkey)


def robot_framework_job(new_job, config_settings, masterkey):
    job_name = os.path.split(new_job)[-1]
    project_name = job_name.split('.')[0]
    reports_dir = config_settings['reports_dir']
    ws_dir = config_settings['ws_dir']

    project_settings = initialize_config(os.path.join(ws_dir, f'{project_name}.settings'))

    email_to = project_settings['email_to']
    uncompressed_rfw = False

    # Uncompressed Robot Framework File
    for compression_type in ['.zip', '.tar', '.tar.gz', '.tgz', '.gz']:
        compressed_file = os.path.join(ws_dir, f'{project_name}{compression_type}')
        if os.path.exists(compressed_file):
            uncompressed_rfw = uncompressed_file(compressed_file, ws_dir)

    compressed_file_name = os.path.basename(compressed_file)
    if not uncompressed_rfw:
        compressed_file_error_subject = str(config_settings['compressed_file_error_subject'])
        compressed_file_error_subject = compressed_file_error_subject.replace('{project_name}', project_name[0:-4])
        compressed_file_error_message = str(config_settings['compressed_file_error_message'])
        compressed_file_error_message = compressed_file_error_message.replace('{project_name}', project_name[0:-4])
        compressed_file_error_message = compressed_file_error_message.replace('{compressed_file}', compressed_file_name)

        send_email(config_settings, email_to,
                   compressed_file_error_subject,
                   compressed_file_error_message,
                   masterkey)

        cleanup_job(project_name, ws_dir)
        return

    burp_pid = run_burpsuite(config_settings['java_dir'], config_settings['burp_dir'],
                             config_settings['burp_temp_dir'], config_settings['ws_dir'], project_name)

    burp_child_pid = get_child_process_ids(burp_pid)[0]

    # Add Environment Variables
    os.environ['PATH'] += os.pathsep + config_settings['browser_driver_dir']
    os.environ['HTTP_PROXY'] = f'http://{config_settings["proxy_host"]}:{config_settings["proxy_port"]}'
    os.environ['HTTPS_PROXY'] = f'http://{config_settings["proxy_host"]}:{config_settings["proxy_port"]}'

    is_robot_framework_running = False
    while is_process_id_running(burp_child_pid):
        if not is_robot_framework_running:
            print(f'\nRunning Robot Framework for {project_name}')
            robot_option = project_settings['robot_option']
            root_dir = os.getcwd()
            python = os.path.join(project_settings['python_dir'], 'python')
            os.chdir(os.path.join(ws_dir, project_name))
            robot_framework_status = subprocess.run(f'{python} {robot_option}', shell=True)
            os.chdir(root_dir)

            if robot_framework_status.returncode != 0:
                print('\nRobot Framework execution completed but encountered some issues.')
            else:
                print('\nRobot Framework execution completed.')

            print('\nPenetrating testing in progress...\n')

            is_robot_framework_running = True

        time.sleep(3)

    terminate_process_id(burp_pid)

    print('\nBurp scan completed...')

    # Remove Environment Variables
    path_directories = os.environ['PATH'].split(os.pathsep)
    if config_settings['browser_driver_dir'] in path_directories:
        path_directories.remove(config_settings['browser_driver_dir'])
    os.environ['PATH'] = os.pathsep.join(path_directories)
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']

    xreport = export_report(config_settings['java_dir'], config_settings['burp_dir'], ws_dir,
                            project_name, config_settings['burp_report_format'])

    if xreport != 0:
        print('\nPenTest Report Exported.')

    burp_report_datetime = datetime.now().strftime('%Y-%m-%d@%H.%M.%S')
    cleanup_job(project_name, ws_dir, reports_dir, burp_report_datetime, True)

    # Send Successful Scan Message
    report_url = f'{config_settings["report_url"]}{project_name}'
    success_scan_subject = str(config_settings['success_scan_subject'])
    success_scan_subject = success_scan_subject.replace('{project_name}', project_name[0:-4])
    success_scan_message = str(config_settings['success_scan_message'])
    success_scan_message = success_scan_message.replace('{project_name}', project_name[0:-4])
    success_scan_message = success_scan_message.replace('{report_url}', report_url)

    send_email(config_settings, email_to,
               success_scan_subject,
               success_scan_message,
               masterkey)


def cypress_job(new_job, config_settings, masterkey):
    job_name = os.path.split(new_job)[-1]
    project_name = job_name.split('.')[0]
    reports_dir = config_settings['reports_dir']
    ws_dir = config_settings['ws_dir']

    project_settings = initialize_config(os.path.join(ws_dir, f'{project_name}.settings'))

    email_to = project_settings['email_to']
    uncompressed_cyp = False

    # Uncompressed Cypress File
    for compression_type in ['.zip', '.tar', '.tar.gz', '.tgz', '.gz']:
        compressed_file = os.path.join(ws_dir, f'{project_name}{compression_type}')
        if os.path.exists(compressed_file):
            uncompressed_cyp = uncompressed_file(compressed_file, ws_dir)
            pass

    compressed_file_name = os.path.basename(compressed_file)
    if not uncompressed_cyp:
        compressed_file_error_subject = str(config_settings['compressed_file_error_subject'])
        compressed_file_error_subject = compressed_file_error_subject.replace('{project_name}', project_name[0:-4])
        compressed_file_error_message = str(config_settings['compressed_file_error_message'])
        compressed_file_error_message = compressed_file_error_message.replace('{project_name}', project_name[0:-4])
        compressed_file_error_message = compressed_file_error_message.replace('{compressed_file}', compressed_file_name)

        send_email(config_settings, email_to,
                   compressed_file_error_subject,
                   compressed_file_error_message,
                   masterkey)

        cleanup_job(project_name, ws_dir)
        return

    burp_pid = run_burpsuite(config_settings['java_dir'], config_settings['burp_dir'],
                             config_settings['burp_temp_dir'], config_settings['ws_dir'], project_name)

    burp_child_pid = get_child_process_ids(burp_pid)[0]

    # Add Environment Variables
    os.environ['CYPRESS_CACHE_FOLDER'] = project_settings['cypress_dir']
    os.environ['HTTP_PROXY'] = f'http://{config_settings["proxy_host"]}:{config_settings["proxy_port"]}'
    os.environ['HTTPS_PROXY'] = f'http://{config_settings["proxy_host"]}:{config_settings["proxy_port"]}'

    is_cypress_running = False
    while is_process_id_running(burp_child_pid):
        if not is_cypress_running:
            print(f'\nRunning Cypress for {project_name}')
            root_dir = os.getcwd()
            os.chdir(os.path.join(ws_dir, project_name))
            cypress_status = subprocess.run(f'npx.cmd cypress run {project_settings["cypress_option"]}', shell=True)
            os.chdir(root_dir)

            if cypress_status.returncode != 0:
                print('\nCypress execution completed but encountered some issues.')
            else:
                print('\nCypress execution completed.')

            print('\nPenetrating testing in progress...\n')

            is_cypress_running = True

        time.sleep(3)

    terminate_process_id(burp_pid)

    print('\nBurp scan completed...')

    # Remove Environment Variables
    del os.environ['CYPRESS_CACHE_FOLDER']
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']

    xreport = export_report(config_settings['java_dir'], config_settings['burp_dir'], ws_dir,
                            project_name, config_settings['burp_report_format'])

    if xreport != 0:
        print('\nPenTest Report Exported.')

    burp_report_datetime = datetime.now().strftime('%Y-%m-%d@%H.%M.%S')
    cleanup_job(project_name, ws_dir, reports_dir, burp_report_datetime, True)

    # Send Successful Scan Message
    report_url = f'{config_settings["report_url"]}{project_name}'
    success_scan_subject = str(config_settings['success_scan_subject'])
    success_scan_subject = success_scan_subject.replace('{project_name}', project_name[0:-4])
    success_scan_message = str(config_settings['success_scan_message'])
    success_scan_message = success_scan_message.replace('{project_name}', project_name[0:-4])
    success_scan_message = success_scan_message.replace('{report_url}', report_url)

    send_email(config_settings, email_to,
               success_scan_subject,
               success_scan_message,
               masterkey)


def selenium_job():
    cls()
    print('Selenium will be available in the future release...')


def process_encryption_mode(encrypt_all_creds):
    if encrypt_all_creds == 'on':
        subprocess.run('python file_encryptor.py -a encrypt', shell=True)
    elif encrypt_all_creds == 'off':
        subprocess.run('python file_encryptor.py -a decrypt', shell=True)
    else:
        print('Never encrypt or decrypt.')


def main():
    ws_dir = ''
    try:
        config_settings = initialize_config('autopt.conf')

        if not config_settings:
            print('Config Settings Initialization Error...')
            exit()

        for operating_dir in [('job_dir', os.path.join(os.getcwd(), 'Job')),
                              ('ws_dir', os.path.join(os.getcwd(), 'WS')),
                              ('repo_dir', os.path.join(os.getcwd(), 'Repo')),
                              ('burp_templates_dir', os.path.join(os.getcwd(), 'Templates')),
                              ('reports_dir', os.path.join(os.getcwd(), 'Reports')),
                              ('secrets_dir', os.path.join(os.getcwd(), 'Secrets')),
                              ('browser_driver_dir', os.path.join(os.getcwd(), 'Drivers'))]:
            if not config_settings[operating_dir[0].strip()]:
                config_settings[operating_dir[0]] = operating_dir[1]

        job_dir = config_settings['job_dir']
        ws_dir = config_settings['ws_dir']
        repo_dir = config_settings['repo_dir']
        burp_templates_dir = config_settings['burp_templates_dir']
        reports_dir = config_settings['reports_dir']
        encrypt_all_creds = str(config_settings['encrypt_all_creds']).lower()
        encryption_mode = str(config_settings['encryption_mode']).lower()
        java_dir = config_settings['java_dir']
        secrets_dir = config_settings['secrets_dir']
        keys_key = config_settings['keys_key']
        gpg_dir = config_settings['gpg_dir']
        passphrase = ''
        masterkey = ''
        proxy_host = config_settings['proxy_host']
        proxy_port = config_settings['proxy_port']
        use_app_burp_file = str(config_settings['use_app_burp_file']).lower()

        if encrypt_all_creds == 'on':
            keys_key = cipher.keys_key(config_settings['keys_key'])
            if encryption_mode == 'simple':
                masterkey = cipher.get_key(java_dir, secrets_dir, 'Keys.jks', keys_key, 'masterkey')
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

        while True:
            new_job = check_new_job(job_dir, repo_dir, burp_templates_dir, ws_dir, reports_dir,
                                    encrypt_all_creds, java_dir, secrets_dir, keys_key, gpg_dir, masterkey, passphrase,
                                    proxy_host, proxy_port, use_app_burp_file)
            if new_job:
                job_name = os.path.split(new_job)[-1]
                project_name = job_name.split('.')[0]
                job_type = project_name[-3:]
                cls()
                if job_type == 'dkr':
                    print('Running Docker Job...')
                    docker_job(new_job, config_settings, masterkey, passphrase)
                elif job_type == 'ccb':
                    print('Running Cucumber Job...')
                    cucumber_job(new_job, config_settings, masterkey)
                elif job_type == 'rfw':
                    print('Running Robot Framework Job...')
                    robot_framework_job(new_job, config_settings, masterkey)
                elif job_type == 'cyp':
                    print('Running Cypress Job...')
                    cypress_job(new_job, config_settings, masterkey)
                elif job_type == 'sel':
                    print('Running Selenium Job...')
                    selenium_job()

                time.sleep(8)

            else:
                cls()
                print('Waiting for PenTest jobs...')
                time.sleep(1)

    except KeyboardInterrupt:
        print('\nCancelled.')
        cleanup_job('Clear', ws_dir)
        exit()


if __name__ == "__main__":
    main()

