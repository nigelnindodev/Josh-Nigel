# We need a parser for the log files
# We will just take some few lines and test the parser

import re

LOG_FILE_NAME = 'assignment.log'
MAX_REQUEST_THRESHOLD = 20
ALGOLIA_BASE_URL = 'https://www.algolia.com'

# One way you would have doe it is to use regexes as shown in this example. But since the log data is spaced out
# uniformly, its easier and more performant to use spaces.
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# After splitting an individual log string, we get array indexes corresponding to some data we are interested in
IP_ADDRESS_INDEX = 0
HTTP_METHOD_INDEX = 5
HTTP_STATUS_CODE_INDEX = 8
ORIGIN_URL_INDEX = 10
BYTE_SIZE_INDEX = 9
USER_AGENT_INDEX = 10

# Data structure to hold values while iterating
ip_address_count = {}
max_request_suspicious = {}
non_200_status_codes = {}
non_origin_url_count = {}


def read_file(file_name):
    lines = None
    with open(file_name) as f:
        lines = f.readlines()
    return lines


# TODO: Remove this, not being used
def extract_regex(line):
    ip_list = re.findall(IP_REGEX, line)
    return ip_list


# Convenience function for printing dict values
def print_dict(dictionary):
    for key, value in dictionary.items():
        print(key, ' => ', value)


def sort_dict_count(dictionary):
    return dict(sorted(dictionary.items(), key=lambda item: item[1], reverse=True))


def sort_dict_items(dictionary):
    return dict(sorted(dictionary.keys(), key=lambda x: dictionary[x], reverse=True))


# Take in the log segments and count how many times and IP address shows up
def ip_address_check(log_segments):
    ip_address = log_segments[IP_ADDRESS_INDEX]
    if ip_address in ip_address_count:
        # increment
        ip_address_count[ip_address] = ip_address_count[ip_address] + 1
    else:
        # initialize
        ip_address_count[ip_address] = 0


def origin_url_check(log_segments):
    origin_url = log_segments[ORIGIN_URL_INDEX]
    if ALGOLIA_BASE_URL not in origin_url:
        ip_address = log_segments[IP_ADDRESS_INDEX]
        if ip_address in non_origin_url_count:
            # increment
            non_origin_url_count[ip_address] = non_origin_url_count[ip_address] + 1
        else:
            # initialize
            non_origin_url_count[ip_address] = 0


# function for report to filter out IP's with many requests
def filter_many_api_request():
    for (key, value) in ip_address_count.items():
        if value > MAX_REQUEST_THRESHOLD:
            max_request_suspicious[key] = value


def status_code_check(log_segments):
    status_code = log_segments[HTTP_STATUS_CODE_INDEX]
    if int(status_code) > 299:
        ip_address = log_segments[IP_ADDRESS_INDEX]
        if ip_address in non_200_status_codes:
            non_200_status_codes[ip_address].append(int(status_code))
        else:
            non_200_status_codes[ip_address] = [int(status_code)]


def main():
    count = 0
    for line in read_file(LOG_FILE_NAME):
        count += 1
        # print(f'line: {line}')
        # print(f'ips: {extract_regex(line)}')
        log_segments = line.split(" ")

        # print(f'Processing line number {count}')

        # IP address check
        ip_address_check(log_segments)
        # Get suspicious IP's
        filter_many_api_request()

        # Check suspicious status codes
        status_code_check(log_segments)

        # Check for unknown origin urls
        origin_url_check(log_segments)

    print("=========================== IP ADDRESS COUNT ===========================")
    print_dict(sort_dict_count(max_request_suspicious))
    print("========================================================================")

    print("=========================== NON 2xx REQUESTS ===========================")
    print_dict(sort_dict_items(non_200_status_codes))
    print("========================================================================")

    print("=========================== NON ORIGIN URL IP's ===========================")
    print_dict(sort_dict_count(non_origin_url_count))
    print("========================================================================")





main()

# For each line we need to separate the various element



