import argparse
import datetime
from datetime import datetime, timedelta
import struct
import sys
import logging
import os
from Registry import Registry
import csv
import codecs
from pathlib import Path
import json

# KEYS will contain sub-lists of each parsed UserAssist (UA) key
KEYS = []
UEME = []
EXE_Files_GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
LNK_Files_GUID = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"


def main(registry, out_file):
    """
    The main function handles main logic of script.
    :param registry: Registry Hive to process
    :param out_file: The output path and file csv file
    :return: Nothing.
    """
    if os.path.basename(registry).lower() != 'ntuser.dat':
        print(f'[-] {registry} filename is incorrect (Should be ntuser.dat')
        logging.error('Incorrect file detected based on name')
        sys.exit(1)
    # Create dictionary of ROT-13 decoded UA key and its value
    apps = createDictionary(registry)
    parseUEME(apps)
    ua_type = parseValues(apps)

    if ua_type == 0:
        logging.info('Detected XP-based Userassist values.')

    else:
        logging.info('Detected Win7-based Userassist values. Contains Focus values.')


     # Get the CSV header from the keys of the first dictionary
    header = KEYS[0].keys()
    with open(out_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=header)
        # Write the header
        writer.writeheader()
        # Write the rows
        writer.writerows(KEYS)


    # Write UEME_CTLSESSION values to json file
    path_obj = Path(out_file)
    out_parent = path_obj.parent.absolute()
    ueme_outfile = os.path.join(out_parent, 'ueme_sessions.json')
    with open(ueme_outfile, mode = 'w') as f:
        json.dump(UEME, f)


def createDictionary(registry):
    """
    The createDictionary function creates a list of dictionaries where GUID as keys and list of dictionaries as values. 
    the values are list of dictionaries where keys are the ROT-13 decoded app names and values are the raw hex data of app's Userassist data.
    :param registry: Registry Hive to process
    :return: apps_list, A list containing dictionaries

    output example:
     [
        {
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": [
                {"Microsoft.Windows.Explorer": `Raw Hex Value`},
                {"Chrome": `Raw Hex Value`}
                ]
        }
    ]

    """
    try:
        # Open the registry file to be parsed
        reg = Registry.Registry(registry)
    except (IOError, Registry.RegistryParse.ParseException) as e:
        msg = 'Invalid NTUSER.DAT path or Registry ID.'
        print(f'[-] {msg}')
        logging.error(msg)
        sys.exit(2)
    try:
        # Navigate to the UserAssist key
        ua_key = reg.open('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
    except Registry.RegistryKeyNotFoundException:
        msg = 'UserAssist Key not found in Registry file.'
        print(f'[-] {msg}')
        logging.error(msg)
        sys.exit(3)
    apps_list = []
    # Loop through each subkey in the UserAssist key
    for ua_subkey in ua_key.subkeys():
        # For each subkey in the UserAssist key, detect if there is a subkey called
        # Count and that it has more than 0 values to parse.
        if ua_subkey.subkey('Count') and ua_subkey.subkey('Count').values_number() > 0:
            guid_keys = {}
            GUID = ua_subkey.name() # Get working GUID subkey 
            apps = {}
            for v in ua_subkey.subkey('Count').values():
                apps[codecs.decode(v.name(), 'rot_13')] = v.raw_data() # create dictionary for apps and their raw hex values 
            guid_keys[GUID] = apps # create dictionary for GUID subkey and their related apps
            apps_list.append(guid_keys)
    return apps_list


def parseValues(data):
    """
    The parseValues function uses struct to unpack the raw value data from the UA key
    :param data: A list containing dictionaries of UA application data
    :return: ua_type, based on the size of the raw data from the dictionary values.
    """
    ua_type = -1
    msg = 'Parsing UserAssist values.'
    print(f'[+] {msg}')
    logging.info(msg)

    # Loop through GUIDs dictionaries 
    for guid in data:
        working_guid = list(guid.keys())[0] 
        if working_guid == EXE_Files_GUID:
            ueme_session = searchUEMESessioninList(EXE_Files_GUID)
        elif working_guid == LNK_Files_GUID:
            ueme_session = searchUEMESessioninList(LNK_Files_GUID)
        else:
            ueme_session = searchUEMESessioninList(working_guid) 


        # calculations concluded from the research (N value) 
        # N value = App's Run Count*(Total User Time/Total Launches) + App's Focus Time + App's Focus Count*(Total User Time/Total Switches)
        try:
            launch_avg = ueme_session['stats']['Total User Time']/ueme_session['stats']['Total Launches']
        except:
            launch_avg = 0 

        try:
            switch_avg = ueme_session['stats']['Total User Time']/ueme_session['stats']['Total Switches']
        except:
            switch_avg = 0
        try:
             N_value_of_most_used_app = ueme_session['NMAX'][2]['Run Count']*launch_avg + ueme_session['NMAX'][2]['Focus Count']*switch_avg + ueme_session['NMAX'][2]['Focus Time']
        except:
            pass

        # Loop through apps in specific working GUID dictionaries 
        for dictionary in guid.values():
            for v in dictionary.keys():
                # WinXP based UA keys are 16 bytes
                if len(dictionary[v]) == 16:
                    raw = struct.unpack('<2iq', dictionary[v])
                    ua_type = 0
                    KEYS.append({'Name': getName(v), 'Path': v, 'Session ID': raw[0], 'Count': raw[1],
                                'Last Used Date (UTC)': raw[2], 'Focus Time (ms)': '', 'Focus Count': ''})
                # Win7 based UA keys are 72 bytes
                elif len(dictionary[v]) == 72:
                    raw = struct.unpack('<4i10fiqi', dictionary[v])
                    ua_type = 1
                    FTHR = convertFocusTimetoHumanReadable(raw[3])
                    N_value_current_session = raw[1]*launch_avg+raw[2]*switch_avg+raw[3] # app's N values for current session
                    R0_value_current_session = N_value_current_session/N_value_of_most_used_app # app's R0 value for current session [R0 value = N Value of the App / N Value of the Most Used App in the session (NMAX Entry 3)]
                    session_usage_perc = N_value_current_session / ueme_session['stats']['Total User Time'] # Just curious calculation for the usage in regards of the total user time
                    KEYS.append({'GUID':working_guid, 'Path': v, 'Session ID': raw[0], 'Run Count': raw[1],
                                'Focus Count': raw[2], 'Focus Time (ms)': raw[3], 'Focus Time (Human-Readable)': f'{FTHR[0]}d, {FTHR[1]}h, {FTHR[2]}m, {FTHR[3]}s, {FTHR[4]}ms','Last Used Date (UTC)': filetime_to_datetime(raw[15]),
                                'N Value of current session': N_value_current_session, 'R0 Value of current session': R0_value_current_session, 'Total Usage Percentage': session_usage_perc,'Rewrite Counter': raw[14],
                                'r0 value[0]': raw[4], 'r0 value[1]': raw[5], 'r0 value[2]': raw[6], 'r0 value[3]': raw[7],
                                'r0 value[4]': raw[8], 'r0 value[5]': raw[9], 'r0 value[6]': raw[10], 'r0 value[7]': raw[11],
                                'r0 value[8]': raw[12], 'r0 value[9]': raw[13], 'unknown': raw[16]})
                else:
                    # If the key is not WinXP or Win7 based -- ignore.
                    msg = 'Skipping ' + str(v) + ' value that is ' + str(len(dictionary[v])) + ' bytes.'
                    print(f'[-] {msg}')
                    logging.info(msg)
                    continue
    return ua_type

def convertFocusTimetoHumanReadable(focustime):
    """
    The convertFocusTimetoHumanReadable will convert focustime from milliseconds to human readable such as 'X days, X hours, X minutes, X seconds, X milliseconds'
    """
    milliseconds = focustime % 1000
    total_seconds = focustime // 1000
    seconds = total_seconds % 60
    total_minutes = total_seconds // 60
    minutes = total_minutes % 60
    total_hours = total_minutes // 60
    hours = total_hours % 24
    days = total_hours // 24
    return (days, hours, minutes, seconds, milliseconds)


def parseUEME(data):
    """
    The parseUEME will parse all UEME_CTLSESSION in every subkeys under Userassist and add it to UEME list
    """

    for guid in data:
        tmp_keys_list = list(guid.keys())
        g = tmp_keys_list[0]
        for dictionary in guid.values():
            if dictionary["UEME_CTLSESSION"] is not None:
                raw = struct.unpack('<4i3i520s3i520s3i520s', dictionary["UEME_CTLSESSION"])
                Total_stats = {'Session ID': raw[0], 'Total Launches': raw[1], 'Total Switches': raw[2], 'Total User Time': raw[3]}

                e1 = raw[7].decode('utf-16').split('\x00', 1)[0]
                e2 = raw[11].decode('utf-16').split('\x00', 1)[0]
                e3 = raw[15].decode('utf-16').split('\x00', 1)[0]

                NMAX_list = [{'Run Count': raw[4], 'Focus Count': raw[5], 'Focus Time': raw[6], 'Executable Path': e1},
                            {'Run Count': raw[8], 'Focus Count': raw[9], 'Focus Time': raw[10], 'Executable Path': e2},
                            {'Run Count': raw[12], 'Focus Count': raw[13], 'Focus Time': raw[14], 'Executable Path': e3}]

                ueme_session = {}
                ueme_session[g] = {'stats': Total_stats, 'NMAX': NMAX_list}
                UEME.append(ueme_session)


def searchUEMESessioninList(guid):
    """
    The searchUEMESessioninList will search all parsed UEME_CTLSESSION values in UEME list for specific GUID and return it
    """
    for ueme_session in UEME:
        if list(ueme_session.keys())[0] == guid:
            tmp_ueme_session = ueme_session[guid]
    return tmp_ueme_session


def filetime_to_datetime(filetime):
    """
    The filetime_to_datetime will convert Windows FILETIME to iso 8601 timestamp
    """
    # Windows FileTime epoch starts from January 1, 1601
    windows_epoch = datetime(1601, 1, 1)

    # Convert filetime (100-nanosecond intervals) to seconds
    seconds = filetime / 10_000_000  # 10,000,000 intervals per second

    # Add the seconds to the Windows epoch to get the corresponding datetime
    dt = windows_epoch + timedelta(seconds=seconds)
    return dt.isoformat() + 'Z'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('REGISTRY', help='NTUSER Registry Hive.')
    parser.add_argument('OUTPUT', help='Output file (.csv or .xlsx)')
    parser.add_argument('-l', help='File path of log file.')

    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'userassist_parser.log')
    else:
        log_path = 'userassist_parser.log'
    main(args.REGISTRY, args.OUTPUT)