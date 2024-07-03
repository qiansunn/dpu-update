## Dpu update Script

This repository is created only for reference code and example.

  OobUpdate.sh - BlueField DPU Update Script (out-of-band)

## Description

OobUpdate.sh is a program for updating various component firmware of BlueField DPU, like BMC, CEC and BIOS. It works from out of band, uses RedFish API exposed by BMC of DPU. The script can work from any controller host (Linux), which has available connection to the DPU BMC system.

## Usage

    OobUpdate.sh [-h] [-U <username>] [-P <password>] [-F <firmware_file>]
                 [-T <module>] [-H <bmc_ip>] [-C <clear_config>]
                 [-o <output_log_file>] [-p <bmc_port>] [-v]
                 [--skip_same_version] [-d]

    optional arguments:
      -h, --help            show this help message and exit
      -U <username>         Username of BMC
      -P <password>         Password of BMC
      -F <firmware_file>    Firmware file path (absolute/relative)
      -T <module>           The module to be updated: BMC|CEC|BIOS
      -H <bmc_ip>           IP/Host of BMC
      -C                    Reset to factory configuration (Only used for BMC|BIOS)
      -o <output_log_file>, --output <output_log_file>
                            Output log file
      -p <bmc_port>, --port <bmc_port>
                            Port of BMC
      -v, --version         Show the version of this scripts
      --skip_same_version   Do not upgrade, if upgrade version is the same as
                            current running version
      -d, --debug           Show more debug info

## Example
Update BMC firmware

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98  -T BMC -F /opt/bf3-bmc-24.04-5_ipn.fwpkg
    Start to upload firmware
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Restart BMC to make new firmware take effect
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    OLD BMC Firmware Version:
            BF-24.03-4
    New BMC Firmware Version:
            BF-24.04-5

Update CEC firmware

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98  -T CEC -F /opt/cec1736-ecfw-00.02.0182.0000-n02-rel-debug.fwpkg
    Start to upload firmware
    Process|: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Restart CEC to make new firmware take effect
    Process|: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    OLD CEC Firmware Version:
            00.02.0180.0000_n02
    New CEC Firmware Version:
            00.02.0182.0000_n02

Update BIOS firmware

    # ./OobUpdate.sh -U root -P Nvidia20240604-- -H 10.237.121.98  -T BIOS -F /opt/BlueField-4.7.0.13127_preboot-install.bfb
    Start to upload firmware
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Wait for BIOS ready
    Process-: 100%: ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    Old BIOS Firmware Version:
            ATF--v2.2(release):4.8.0-14-gc58efcd, UEFI--4.8.0-11-gbd389cc
    New BIOS Firmware Version:
            ATF--v2.2(release):4.7.0-25-g5569834, UEFI--4.7.0-42-g13081ae


## Precondition (Controller Host)
1. Avaiable connection to DPU BMC
2. Python3 is needed, with requests module installed


## Precondition (Target DPU BMC)
1. User&password of DPU BMC is workable. Default user&password need to be updated in advance
2. The BMC firmware version should be >= 24.04

## Precondition (Host in which DPU plugged)
1. Rshim on Host need to be disabled, if want to update the BIOS of DPU
