#!/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024, NVIDIA CORPORATION. All rights reserved.


"""
python3 -m pip install requests
or install from local packages:
python3 -m pip install --no-index --find-links=./packages requests
"""

import time
import re
import sys
import os
import json
import socket
import requests
import getpass
import subprocess
import stat
from enum import Enum
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Number to trace various error
class Err_Num(Enum):
    ERR_NONE                              = 0
    ARG_FOR_UPDATE_NOT_GIVEN              = 1
    ARG_FOR_VERSION_NOT_GIVEN             = 2
    FILE_NOT_ACCESSIBLE                   = 3
    FW_FILE_NOT_MATCH_MODULE              = 4
    BMC_CONNECTION_FAIL                   = 5
    BMC_CONNECTION_RESET                  = 6
    BMC_CONNECTION_OTHER_ERR              = 7
    ACCOUNT_LOCKED                        = 8
    INVALID_USERNAME_OR_PASSWORD          = 9
    ANOTHER_UPDATE_IS_IN_PROGRESS         = 10
    UNSUPPORTED_MODULE                    = 11
    BAD_RESPONSE_FORMAT                   = 12
    EMPTY_FW_VER                          = 13
    INVALID_STATUS_CODE                   = 14
    FAILED_TO_GET_LOCAL_KEY               = 15
    FAILED_TO_ENABLE_BMC_RSHIM            = 16
    NOT_SUPPORT_CEC_RESTART               = 17
    BMC_BACKGROUND_BUSY                   = 18
    PUBLIC_KEY_NOT_EXCHANGED              = 19
    TASK_FAILED                           = 20
    NEW_VERION_CHECK_FAILED               = 21
    FAILED_TO_GET_VER_FROM_FILE           = 22
    FAILED_TO_START_HTTP_SERVER           = 23
    NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL    = 24
    BIOS_FACTORY_RESET_FAIL               = 25
    TASK_TIMEOUT                          = 26
    OTHER_EXCEPTION                       = 127


Err_Str = {
   Err_Num.ARG_FOR_UPDATE_NOT_GIVEN       : 'BMC IP/Username/Password, Firmware file path and Module are needed to do firmware update',
   Err_Num.ARG_FOR_VERSION_NOT_GIVEN      : 'BMC IP/Username/Password are needed to show versions of all firmwares',
   Err_Num.FILE_NOT_ACCESSIBLE            : 'File is not accessible',
   Err_Num.FW_FILE_NOT_MATCH_MODULE       : 'Firmware file is NOT for the module to update',
   Err_Num.BMC_CONNECTION_FAIL            : 'Failed to establish connection to BMC. Please check the BMC IP and port',
   Err_Num.BMC_CONNECTION_RESET           : 'Connection to BMC being reset by remove',
   Err_Num.BMC_CONNECTION_OTHER_ERR       : 'Connection failed',
   Err_Num.ACCOUNT_LOCKED                 : 'Account has been locked',
   Err_Num.INVALID_USERNAME_OR_PASSWORD   : 'Invalid username or password',
   Err_Num.ANOTHER_UPDATE_IS_IN_PROGRESS  : 'Another update is in progress',
   Err_Num.UNSUPPORTED_MODULE             : 'Unsupported updating module',
   Err_Num.BAD_RESPONSE_FORMAT            : 'Bad response format',
   Err_Num.EMPTY_FW_VER                   : 'Empty firmware version in response',
   Err_Num.INVALID_STATUS_CODE            : 'Invalid response status code',
   Err_Num.FAILED_TO_GET_LOCAL_KEY        : 'Failed to get local SSH Key',
   Err_Num.FAILED_TO_ENABLE_BMC_RSHIM     : 'Failed to enable BMC rshim',
   Err_Num.NOT_SUPPORT_CEC_RESTART        : 'CEC restart redfish API is not supported in this version',
   Err_Num.BMC_BACKGROUND_BUSY            : 'BMC is busy on background operation',
   Err_Num.PUBLIC_KEY_NOT_EXCHANGED       : 'Public key was not exchanged with BMC successfully',
   Err_Num.TASK_FAILED                    : 'Task failed',
   Err_Num.NEW_VERION_CHECK_FAILED        : 'New running version check failed',
   Err_Num.FAILED_TO_GET_VER_FROM_FILE    : 'Failed to get firmware version from file',
   Err_Num.FAILED_TO_START_HTTP_SERVER    : 'Failed to start HTTP server',
   Err_Num.NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL : 'NO supported BFB update protocol',
   Err_Num.BIOS_FACTORY_RESET_FAIL        : 'Failed to do BIOS factory reset',
   Err_Num.TASK_TIMEOUT                   : 'Task timeout',
   Err_Num.OTHER_EXCEPTION                : 'Other Errors',
}


class Err_Exception(Exception):
    def __init__(self, err_num, msg=None):
        self.err_num = err_num
        self.msg     = msg
    def __str__(self):
        return Err_Str[self.err_num] + (('; ' + self.msg + '.') if self.msg is not None else '')


class BF_DPU_Update(object):
    module_resource = {
        'BMC'       : 'BMC_Firmware',
        'CEC'       : 'Bluefield_FW_ERoT',
        'ATF'       : 'DPU_ATF',
        'UEFI'      : 'DPU_UEFI',
        'BSP'       : 'DPU_BSP',
        'NIC'       : 'DPU_NIC',
        'NODE'      : 'DPU_NODE',
        'OFED'      : 'DPU_OFED',
        'OS'        : 'DPU_OS',
        'SYS_IMAGE' : 'DPU_SYS_IMAGE',
        'ARM_IMAGE' : 'golden_image_arm',
        'NIC_IMAGE' : 'golden_image_nic',
        'BOARD'     : 'DPU_BOARD'
    }


    def __init__(self, bmc_ip, bmc_port, username, password, fw_file_path, module, skip_same_version, debug=False, log_file=None):
        self.bmc_ip            = bmc_ip
        self.bmc_port          = bmc_port
        self.username          = username
        self.password          = password
        self.fw_file_path      = fw_file_path
        self.module            = module
        self.skip_same_version = skip_same_version
        self.debug             = debug
        self.log_file          = log_file
        self.protocol          = 'https://'
        self.redfish_root      = '/redfish/v1'
        self.process_flag      = True
        self._local_http_server_port = None


    def _get_url_base(self):
        port = '' if self.bmc_port is None else ':{}'.format(self.bmc_port)
        return self.protocol + self.bmc_ip + port + self.redfish_root


    def _get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((self.bmc_ip, 0))
        return s.getsockname()[0]


    def _get_local_user(self):
        return getpass.getuser()


    def _get_truncated_data(self, data):
        if len(data) > 1024:
            return data[0:1024] + '... ... [Truncated]'
        else:
            return data


    def log(self, msg, resp):
        data  = '[======== ' + msg + ' ========]: ' + '\n'
        data += '[Request Line]: ' + '\n'
        data += str(resp.request.method) + ' ' + resp.url + '\n'
        data += '[Request Headers]:' + '\n'
        data += str(resp.request.headers) + '\n'
        data += '[Request Body]:' + '\n'
        data += self._get_truncated_data(str(resp.request.body)) + '\n'
        data += "[Response status line]:" + '\n'
        data += str(resp.status_code) + ' ' + resp.reason + '\n'
        data += "[Response Headers]:" + '\n'
        data += json.dumps(str(resp.headers), indent=4) + '\n'
        data += "[Response Body]:" + '\n'
        data += resp.text + '\n'

        if self.debug:
            print(data, end='')
        if self.log_file is not None:
            with open(self.log_file, 'a') as f:
                f.write(data)


    def connection_exception(func):
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except requests.exceptions.ConnectTimeout as timeout:
                raise Err_Exception(Err_Num.BMC_CONNECTION_FAIL)
            except requests.exceptions.ConnectionError as connect_err:
                raise Err_Exception(Err_Num.BMC_CONNECTION_RESET)
            except Exception as e:
                raise Err_Exception(Err_Num.BMC_CONNECTION_OTHER_ERR, str(e))
        return wrapper


    @connection_exception
    def _http_get(self, url, headers=None, timeout=(60, 60)):
        return requests.get(url,
                            headers=headers,
                            auth=(self.username, self.password),
                            verify=False,
                            timeout=timeout)


    @connection_exception
    def _http_post(self, url, data=None, files=None, headers=None, timeout=(60, 60)):
        return requests.post(url,
                             data=data,
                             files=files,
                             headers=headers,
                             auth=(self.username, self.password),
                             verify=False,
                             timeout=timeout)


    @connection_exception
    def _http_patch(self, url, data, headers=None, timeout=(60, 60)):
        return requests.patch(url,
                              data=data,
                              headers=headers,
                              auth=(self.username, self.password),
                              verify=False,
                              timeout=timeout)


    def _handle_status_code(self, response, acceptable_codes, err_handler=None):
        if response.status_code in acceptable_codes:
            return

        try:
            msg = response.json()['error']['message']
        except:
            msg = ''

        # Raise exception for different cases
        if response.status_code == 401:
            if 'Account temporarily locked out' in msg:
                raise Err_Exception(Err_Num.ACCOUNT_LOCKED, msg)
            elif 'Invalid username or password' in msg:
                raise Err_Exception(Err_Num.INVALID_USERNAME_OR_PASSWORD, msg)

        if err_handler is not None:
            err_handler(response)

        raise Err_Exception(Err_Num.INVALID_STATUS_CODE, 'status code: {}; {}'.format(response.status_code, msg))


    def get_ver(self, module):
        url = self._get_url_base() + '/UpdateService/FirmwareInventory/' + self.module_resource[module]
        response = self._http_get(url)
        self.log('Get {} Firmware Version'.format(module), response)
        self._handle_status_code(response, [200])

        ver = ''
        try:
            ver = response.json()['Version']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract firmware version')

        return ver


    def _extract_task_handle(self, response):
        '''
        {
            "@odata.id": "/redfish/v1/TaskService/Tasks/6",
            "@odata.type": "#Task.v1_4_3.Task",
            "Id": "6",
            "TaskState": "Running",
            "TaskStatus": "OK"
        }
        '''
        try:
            return response.json()["@odata.id"]
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract task handle')


    def get_simple_update_protocols(self):
        url = self._get_url_base() + '/UpdateService'
        response = self._http_get(url)
        self.log('Get UpdateService Attribute', response)
        self._handle_status_code(response, [200])

        protocols = []
        '''
        {
          ...
          "Actions": {
            "#UpdateService.SimpleUpdate": {
              "TransferProtocol@Redfish.AllowableValues": [
                "SCP",
                "HTTP",
                "HTTPS"
              ],
            },
          }
          ...
        }
        '''
        try:
            protocols = response.json()['Actions']['#UpdateService.SimpleUpdate']['TransferProtocol@Redfish.AllowableValues']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract SimpleUpdate protocols')
        return protocols


    @staticmethod
    def _update_in_progress_err_handler(response):
        try:
            msg = response.json()['error']['message']
        except:
            msg = ''

        if response.status_code == 400:
            if 'An update is in progress' in msg:
                raise Err_Exception(Err_Num.ANOTHER_UPDATE_IS_IN_PROGRESS, 'Please try to update the firmware later')


    def update_bfb(self):
        protocols = self.get_simple_update_protocols()
        if 'HTTP' in protocols:
            return ('HTTP', self.update_bfb_by_http())
        elif 'SCP' in protocols:
            return ('SCP', self.update_bfb_by_scp())
        raise Err_Exception(Err_Num.NOT_SUPPORT_SIMPLE_UPDATE_PROTOCOL, 'The current BFB update protocols are {}'.format(protocols))


    def update_bfb_impl(self, protocol, image_uri):
        url = self._get_url_base() + '/UpdateService/Actions/UpdateService.SimpleUpdate'
        headers = {
            'Content-Type'     : 'application/json'
        }
        data = {
            'TransferProtocol' : protocol,
            'ImageURI'         : image_uri,
            'Targets'          : ['redfish/v1/UpdateService/FirmwareInventory/DPU_OS'],
            'Username'         : self._get_local_user()
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Update BFB Firmware', response)
        self._handle_status_code(response, [202], self._update_in_progress_err_handler)
        return self._extract_task_handle(response)


    def update_bfb_by_scp(self):
        self.confirm_ssh_key_with_bmc()
        print("Start to upload BFB firmware (SCP)")
        return self.update_bfb_impl('SCP', self._get_local_ip() + '/' + os.path.abspath(self.fw_file_path))


    def http_server(self):
        debug = self.debug
        from http.server import HTTPServer, SimpleHTTPRequestHandler
        class _SimpleHTTPRequestHandler(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                if debug:
                    super().log_message(format, *args)

        abs_dir = os.path.dirname(os.path.abspath(self.fw_file_path))
        os.chdir(abs_dir)
        httpd = HTTPServer((self._get_local_ip(), 0), _SimpleHTTPRequestHandler)
        self._local_http_server_port = httpd.server_address[1]
        httpd.serve_forever()


    def create_http_server_thread(self):
        import threading
        thread = threading.Thread(target=self.http_server, daemon=True)
        thread.start()
        time.sleep(2) # Wait thread start and set the port.
        if self._local_http_server_port is None:
            raise Err_Exception(Err_Num.FAILED_TO_START_HTTP_SERVER)


    def update_bfb_by_http(self):
        self.create_http_server_thread()
        print("Start to upload BFB firmware (HTTP)")
        return self.update_bfb_impl('HTTP', self._get_local_ip() + ':' + str(self._local_http_server_port) + '//' + os.path.basename(self.fw_file_path))


    def update_bmc_fw_multipart(self):
        url = self._get_url_base() + '/UpdateService/update-multipart'
        with open(self.fw_file_path, 'rb') as fw_file:
            params  = {
                "ForceUpdate": not self.skip_same_version
            }
            files = {
                'UpdateParameters' : json.dumps(params),
                'UpdateFile'       : fw_file,
            }
            response = self._http_post(url, files=files)

        self.log('Update Firmware', response)
        self._handle_status_code(response, [202], self._update_in_progress_err_handler)
        return self._extract_task_handle(response)


    def update_bmc_fw_simple(self):
        url = self._get_url_base() + '/UpdateService'
        headers = {
            'Content-Type' : 'application/octet-stream'
        }
        with open(self.fw_file_path, 'rb') as fw_file:
            response = self._http_post(url, data=fw_file, headers=headers)
        self.log('Update Firmware', response)
        self._handle_status_code(response, [202], self._update_in_progress_err_handler)
        return self._extract_task_handle(response)


    def _get_task_status(self, task_handle):
        task_handle = task_handle[len(self.redfish_root):]
        url = self._get_url_base() + task_handle
        response = self._http_get(url)
        self.log('Get Task Satatus', response)
        self._handle_status_code(response, [200])

        '''
        {
            "PercentComplete": 0,
            "StartTime": "2024-06-05T13:16:37+00:00",
            "TaskMonitor": "/redfish/v1/TaskService/Tasks/11/Monitor",
            "TaskState": "Running",
            "TaskStatus": "OK"
        }
        '''
        try:
            percent = response.json()['PercentComplete']
            state   = response.json()['TaskState']
            status  = response.json()['TaskStatus']
            message = response.json()['Messages']
            return {'state': state, 'status': status, 'percent': percent, 'message': str(message)}
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract task status')


    def reboot_bmc(self):
        print("Restart BMC to make new firmware take effect")
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Actions/Manager.Reset'
        headers = {
            'Content-Type' : 'application/octet-stream'
        }
        data = {
            'ResetType' : 'GracefulRestart'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Reboot BMC', response)
        self._handle_status_code(response, [200])
        self._sleep_with_process(100)


    def reboot_cec(self):
        print("Restart CEC to make new firmware take effect")
        url = self._get_url_base() + '/Chassis/Bluefield_ERoT/Actions/Chassis.Reset'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'ResetType' : 'GracefulRestart'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Reboot CEC', response)
        self._handle_status_code(response, [200, 400])
        if response.status_code == 400:
            raise Err_Exception(Err_Num.NOT_SUPPORT_CEC_RESTART, 'Please use power cycle of the whole system instead')

        self._sleep_with_process(120)


    def factory_reset_bmc(self):
        print("Factory reset BMC configuration")
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Actions/Manager.ResetToDefaults'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'ResetToDefaultsType' : 'ResetAll'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Factory Reset BMC', response)
        self._handle_status_code(response, [200])
        self._sleep_with_process(100)


    def _print_process(self, percent):
        print('\r', end='')
        flag = '|' if self.process_flag else '-'
        self.process_flag = not self.process_flag
        print('Process%s: %3d%%:'%(flag, percent), '░' * (percent // 2), end='')


    def _sleep_with_process_with_percent(self, sec, start_percent=0, end_percent=100):
        for i in range(1, sec+1):
            time.sleep(1)
            self._print_process(start_percent + ((i * (end_percent - start_percent)) // sec))


    def _sleep_with_process(self, sec):
        self._sleep_with_process_with_percent(sec)
        print()


    def _extract_ver_from_fw_file(self, pattern):
        file_name = os.path.basename(self.fw_file_path)
        match     = re.search(pattern, file_name)
        substring = match.group(0)
        return substring


    def extract_cec_ver_from_fw_file(self):
        return self._extract_ver_from_fw_file(r'\d\d.\d\d.\d\d\d\d.\d\d\d\d')


    def extract_bmc_ver_from_fw_file(self):
        return self._extract_ver_from_fw_file(r'\d\d.\d\d-\d')


    def extract_atf_uefi_ver_from_fw_file(self):
        command = 'strings {} | grep -m 1 "(\(release\|debug\))"'.format(self.fw_file_path)
        process   = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            raise Err_Exception(Err_Num.FAILED_TO_GET_VER_FROM_FILE, 'Command "{}" failed with return code {}'.format(command, process.returncode))

        return str(out.decode()).strip()


    def is_fw_file_for_bmc(self):
        command  = 'strings {} | grep -i apfw'.format(self.fw_file_path)
        process  = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            return False
        return True


    def is_fw_file_for_cec(self):
        command  = 'strings {} | grep -i ecfw'.format(self.fw_file_path)
        process  = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            return False
        return True


    def is_fw_file_for_atf_uefi(self):
        try:
            self.extract_atf_uefi_ver_from_fw_file()
        except:
            return False
        return True


    # return True:  task completed successfully
    # return False: task cancelled for skip_same_version
    def _wait_task(self, task_handle, max_second=15*60, check_step=10):
        # Check the task status within a loop
        for i in range(1, max_second//check_step + 1):
            task_state = self._get_task_status(task_handle)
            if task_state['state'] != "Running":
                break
            self._print_process(task_state['percent'])
            time.sleep(check_step)

        # Check the task is completed successfully
        if task_state['state'] == 'Completed' and task_state['status'] == 'OK' and task_state['percent'] == 100:
            self._print_process(100)
            print()
        elif task_state['state'] == 'Running':
            raise Err_Exception(Err_Num.TASK_TIMEOUT, "The task {} is timeout".format(task_handle))
        else:
            if 'Component image is identical' in task_state['message']:
                return False
            elif 'Wait for background copy operation' in task_state['message']:
                raise Err_Exception(Err_Num.BMC_BACKGROUND_BUSY, 'Please try to update the firmware later')
            elif "Please provide server's public key using PublicKeyExchange" in task_state['message']:
                raise Err_Exception(Err_Num.PUBLIC_KEY_NOT_EXCHANGED)
            else:
                raise Err_Exception(Err_Num.TASK_FAILED, task_state['message'])
        return True


    def validate_arg_for_update(self):
        if any(v is None for v in (self.username, self.password, self.fw_file_path, self.module, self.bmc_ip)):
            raise Err_Exception(Err_Num.ARG_FOR_UPDATE_NOT_GIVEN)

        if not os.access(self.fw_file_path, os.R_OK):
            raise Err_Exception(Err_Num.FILE_NOT_ACCESSIBLE, 'Firmware file: {}'.format(self.fw_file_path))

        if self.log_file is not None and not os.access(self.log_file, os.W_OK) and not os.access(os.path.dirname(self.log_file), os.W_OK):
            raise Err_Exception(Err_Num.FILE_NOT_ACCESSIBLE, 'Log file: {}'.format(self.log_file))
        return True


    def is_bmc_background_copy_in_progress(self):
        url = self._get_url_base() + '/Chassis/Bluefield_ERoT'
        response = self._http_get(url)
        self.log('Get ERoT status', response)
        self._handle_status_code(response, [200])

        '''
        {
          ...
          "Oem": {
            "Nvidia": {
              "@odata.type": "#NvidiaChassis.v1_0_0.NvidiaChassis",
              "AutomaticBackgroundCopyEnabled": true,
              "BackgroundCopyStatus": "Completed",
              "InbandUpdatePolicyEnabled": true
            }
          },
          ...
        }
        '''
        status = ''
        try:
            status = response.json()['Oem']['Nvidia']['BackgroundCopyStatus']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract BackgroundCopyStatus')

        if status != 'Completed':
            return True
        else:
            return False


    def update_bmc_or_cec(self, is_bmc):
        self.validate_arg_for_update()

        # Check firmare file is for BMC/CEC
        correct_file = self.is_fw_file_for_bmc() if is_bmc else self.is_fw_file_for_cec()
        if not correct_file:
            raise Err_Exception(Err_Num.FW_FILE_NOT_MATCH_MODULE)

        old_ver = self.get_ver('BMC') if is_bmc else self.get_ver('CEC')
        if old_ver == '':
            raise Err_Exception(Err_Num.EMPTY_FW_VER, 'Get empty {} version'.format('BMC' if is_bmc else 'CEC'))

        if self.is_bmc_background_copy_in_progress():
            raise Err_Exception(Err_Num.BMC_BACKGROUND_BUSY, 'Please try to update the firmware later')

        # Start firmware update task
        print("Start to upload firmware")
        task_handle = self.update_bmc_fw_multipart()
        ret = self._wait_task(task_handle, max_second=(20*60 if is_bmc else 4*60), check_step=(10 if is_bmc else 2))
        if not ret:
            print("Skip updating the same version: {}".format(old_ver))
            return

        # Reboot bmc/cec
        self.reboot_bmc() if is_bmc else self.reboot_cec()

        new_ver = self.get_ver('BMC') if is_bmc else self.get_ver('CEC')
        print('OLD {} Firmware Version: \n\t{}'.format(('BMC' if is_bmc else 'CEC'), old_ver))
        print('New {} Firmware Version: \n\t{}'.format(('BMC' if is_bmc else 'CEC'), new_ver))


    def is_rshim_enabled_on_bmc(self):
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Oem/Nvidia'
        headers = {
            'Content-Type' : 'application/json'
        }
        response = self._http_get(url, headers=headers)
        self.log('Get rshim enable state', response)
        self._handle_status_code(response, [200])

        try:
            return response.json()['BmcRShim']['BmcRShimEnabled']
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract BmcRShimEnabled')


    def enable_rshim_on_bmc(self, enable):
        url = self._get_url_base() + '/Managers/Bluefield_BMC/Oem/Nvidia'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            "BmcRShim": { "BmcRShimEnabled": enable }
        }
        response = self._http_patch(url, json.dumps(data), headers=headers)
        self.log('{} rshim on BMC'.format("Enable" if enable else "Disable"), response)
        self._handle_status_code(response, [200])


    def try_enable_rshim_on_bmc(self):
        if self.is_rshim_enabled_on_bmc():
            return True
        print("Try to enable rshim on BMC")
        self.enable_rshim_on_bmc(True)
        self._sleep_with_process_with_percent(10, 0, 30)
        if self.is_rshim_enabled_on_bmc():
            self._sleep_with_process_with_percent(1, 30, 100)
            print()
            return True

        # Try again if failed
        self.enable_rshim_on_bmc(False)
        self._sleep_with_process_with_percent(10, 30, 60)
        self.enable_rshim_on_bmc(True)
        self._sleep_with_process_with_percent(10, 60, 90)
        if self.is_rshim_enabled_on_bmc():
            self._sleep_with_process_with_percent(1, 90, 100)
            print()
            return True
        print()
        return False


    def _wait_for_bios_ready(self):
        print('Wait for BIOS ready')
        for i in range(1, 101):
            ver = self.get_ver('ATF')
            if ver != '':
                self._print_process(100)
                break
            else:
                self._print_process(i)
                time.sleep(2)
        print()


    def get_local_user_ssh_pub_key(self):
        file_path = os.path.expanduser("~") + '/.ssh/*.pub'
        command   = 'cat {}'.format(file_path)
        process   = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            raise Err_Exception(Err_Num.FAILED_TO_GET_LOCAL_KEY, 'Command "{}" failed with return code {}'.format(command, process.returncode))

        '''
        ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPX0TIi99it4LIChnDwYjuQei03UUTb8izM7KHwsKjd9lUCdYR3ODI8ytEzae4v1nZgyZQuU4cQ/hHF+nhGeQEk= xxx@xxx-435
        '''
        try:
            key_list  = out.decode().split('\n')
            return ' '.join(key_list[0].split(' ')[0:2])
        except:
            raise Err_Exception(Err_Num.FAILED_TO_GET_LOCAL_KEY, 'There may be no ssh-key locally (for user {}). Please run ssh-keygen firstly'.format(self.get_local_user()))


    def exchange_ssh_key_with_bmc(self, local_key):
        url = self._get_url_base() + "/UpdateService/Actions/Oem/NvidiaUpdateService.PublicKeyExchange"
        headers = {
            'Content-Type' : 'application/json'
        }
        msg = {
          "RemoteServerIP"        : "10.237.121.60",
          "RemoteServerKeyString" : local_key,
        }
        response = self._http_post(url, data=json.dumps(msg), headers=headers)
        self.log('Exchange SSH key with BMC', response)
        self._handle_status_code(response, [200])

        '''
        {
            "@Message.ExtendedInfo":
            [
                {
                    "@odata.type": "#Message.v1_1_1.Message",
                    "Message": "Please add the following public
                    key info to ~/.ssh/authorized_keys on the
                    remote server",
                    "MessageArgs": [
                        "<type> <bmc_public_key> root@dpu-bmc"
                    ]
                },
                {
                    ....
                }
            ]
        }
        '''
        try:
            return response.json()['@Message.ExtendedInfo'][0]['MessageArgs'][0]
        except:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract BMC SSH key')


    def is_bmc_key_in_local_authorized_keys(self, bmc_key):
        file_path = os.path.expanduser("~") + '/.ssh/authorized_keys'
        process = subprocess.Popen('grep "{}" {}'.format(bmc_key, file_path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            return False
        return True


    def set_bmc_key_into_local_authorized_keys(self, bmc_key):
        file_path = os.path.expanduser("~") + '/.ssh/authorized_keys'

        # Check and set write permission for ~/.ssh/authorized_keys
        old_permission = None
        if not os.access(file_path, os.W_OK):
            old_permission = os.stat(file_path).st_mode
            os.chmod(file_path, old_permission | stat.S_IWUSR)

        # Append the bmc key into authorized_keys
        with open(file_path, 'a') as f:
            f.write(bmc_key + '\n')

        # Recover the permission
        if old_permission is not None:
            os.chmod(file_path, old_permission)
            old_permission = os.stat(file_path).st_mode


    def confirm_ssh_key_with_bmc(self):
        local_key = self.get_local_user_ssh_pub_key()
        bmc_key   = self.exchange_ssh_key_with_bmc(local_key)
        if self.is_bmc_key_in_local_authorized_keys(bmc_key):
            return
        self.set_bmc_key_into_local_authorized_keys(bmc_key)


    def update_bios(self):
        self.validate_arg_for_update()

        if not self.is_fw_file_for_atf_uefi():
            raise Err_Exception(Err_Num.FW_FILE_NOT_MATCH_MODULE)

        # Skip the same firmware version, if need
        cur_atf_ver  = self.get_ver('ATF')
        cur_uefi_ver = self.get_ver('UEFI')
        if cur_atf_ver is None or cur_uefi_ver is None:
            raise Err_Exception(Err_Num.EMPTY_FW_VER, 'Get empty ATF/UEFI version')

        # Currently, we can only extract atf version from the fw file.
        # So, only do the same_version_check on atf version. Given the
        # assumption that atf verion and uefi version should change at
        # the same time within a package.
        fw_file_atf_ver = self.extract_atf_uefi_ver_from_fw_file()
        if self.skip_same_version and cur_atf_ver in fw_file_atf_ver:
            print('Skip updating the same firmware version: ATF--{} UEFI--{}'.format(cur_atf_ver, cur_uefi_ver))
            return

        # Enable rshim on BMC
        if not self.try_enable_rshim_on_bmc():
            raise Err_Exception(Err_Num.FAILED_TO_ENABLE_BMC_RSHIM, 'Please make sure rshim on Host side is disabled')

        protocol, task_handle = self.update_bfb()
        self._wait_task(task_handle, max_second=20*60, check_step=2)
        self._wait_for_bios_ready()

        # Verify new version is the same as the fw file version
        new_atf_ver  = self.get_ver('ATF')
        new_uefi_ver = self.get_ver('UEFI')
        if new_atf_ver not in fw_file_atf_ver:
            raise Err_Exception(Err_Num.NEW_VERION_CHECK_FAILED, 'New BIOS version is not the version we want to update')
        print('Old {} Firmware Version: \n\tATF--{}, UEFI--{}'.format('BIOS', cur_atf_ver, cur_uefi_ver))
        print('New {} Firmware Version: \n\tATF--{}, UEFI--{}'.format('BIOS', new_atf_ver, new_uefi_ver))
        return True


    def send_factory_reset_bios(self):
        url = self._get_url_base() + '/Systems/Bluefield/Bios/Settings'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'Attributes': {
                'ResetEfiVars': True,
            },
        }
        response = self._http_patch(url, data=json.dumps(data), headers=headers)
        self.log('Factory Reset BIOS', response)

        def err_handler(response):
            if response.status_code == 400:
                raise Err_Exception(Err_Num.BIOS_FACTORY_RESET_FAIL, 'Typically, it was caused for not supporting redfish factory reset in this version')

        self._handle_status_code(response, [200], err_handler)


    def reboot_system(self):
        url = self._get_url_base() + '/Systems/Bluefield/Actions/ComputerSystem.Reset'
        headers = {
            'Content-Type' : 'application/json'
        }
        data = {
            'ResetType': 'GracefulRestart'
        }
        response = self._http_post(url, data=json.dumps(data), headers=headers)
        self.log('Reboot BIOS', response)
        self._handle_status_code(response, [204])


    def get_system_power_state(self):
        url = self._get_url_base() + '/Systems/Bluefield'
        response = self._http_get(url)
        self.log('Get System State', response)
        self._handle_status_code(response, [200])

        state = ''
        try:
            state = response.json()['PowerState']
        except Exception as e:
            raise Err_Exception(Err_Num.BAD_RESPONSE_FORMAT, 'Failed to extract system power state')
        return state


    def _wait_for_system_power_on(self, start_progress, end_progress):
        pre_state = self.get_system_power_state()
        for i in range(start_progress+1, end_progress+1):
            new_state = self.get_system_power_state()
            # Since, after reboot command send, the state is changing as following:
            # ...->On->Paused->PoweringOn->On
            # So, we need following two conditions to judge whether the system is On again
            if new_state != pre_state and new_state  == 'On':
                self._print_process(end_progress)
                break
            else:
                self._print_process(i)
                time.sleep(4)
            pre_state = new_state


    def factory_reset_bios(self):
        print("Factory reset BIOS configuration (will reboot the system)")
        self.send_factory_reset_bios()
        # Reboot twice is needed, according to the workflow
        self.reboot_system()
        self._wait_for_system_power_on(0, 50)
        self.reboot_system()
        self._wait_for_system_power_on(50, 100)
        print()


    def do_update(self):
        if self.module == 'BMC' or self.module == "CEC":
            self.update_bmc_or_cec((self.module == 'BMC'))
        elif self.module == 'BIOS':
            self.update_bios()
        else:
            raise Err_Exception(Err_Num.UNSUPPORTED_MODULE, "Unsupported module: {}".format(self.module))


    def show_all_versions(self):
        if any(v is None for v in (self.username, self.password, self.bmc_ip)):
            raise Err_Exception(Err_Num.ARG_FOR_VERSION_NOT_GIVEN)

        vers = {}
        for module, resouce in self.module_resource.items():
            vers[module] = self.get_ver(module)

        for module, ver in vers.items():
            print("%10s : %40s"%(module, ver))
