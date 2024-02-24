"""
PURPOSE: This script will extract specified IOC's from a document or webpage using regular expressions and then put them into a Splunk query. An analyst
will now be able to specifiy a document and have an immediate output to paste into Splunk as oppossed to copy and pasting each IOC from a document or
webpage.
"""
# AUTHOR: https://github.com/SqlProgrammer55

import pandas as pd
from datetime import datetime
import re, requests, urllib3
import fitz
from os import startfile
urllib3.disable_warnings() # disables potential invasive warnings that pertain any code utilizing the urllib3 library. 
#----------------------------------------------------------------------------------------------------------------------#

new_list = []        # Global list container
now = datetime.now() 

    # REGEX is entirely its own subject matter, that deserves its own discourse, but not in this code.
    # Admittedly as of writing this, the following regex class, is a modification of suggestions from colleagues and external resources. 
    # Treat the following as some esoteric programming magic, it just works.
    # Do not change or modify unless you know what you are doing.
class regex:
    ip_reg = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
    sha_256_reg = re.compile(r'\b[a-fA-F0-9]{64}\b')
    sha_1_reg = re.compile(r'\b[a-fA-F0-9]{40}\b')
    md5_reg = re.compile(r'\b[a-fA-F0-9]{32}\b')
    http_reg = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    email_reg = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    domain_reg = r'\b[a-zA-Z0-9]+\.[a-zA-Z]{2,}\b'
    path_file_reg = r'(?:[a-zA-Z]:[\\/]|\b)(?:[\\/][a-zA-Z0-9_-]+)*(?:[\\/][a-zA-Z0-9_-]+\.[a-zA-Z0-9]+)' 

    reg_list = [ip_reg, sha_256_reg, sha_1_reg, md5_reg, http_reg, email_reg, domain_reg, path_file_reg]
        # references the function "Splunk_Output" on the code below. 

def csv_read(arg, datafield): 
    try:
        match_fix = []
        df = pd.read_csv(arg, skipinitialspace=True, usecols=[datafield])
        matches = df[datafield].tolist()
        for i in matches:
            i = i.replace('[.]', '.') #Takes the any defanged data and re-fangs for text output.
            match_fix.append(i)
        to_new(match_fix)
    except:
        print("\nFile Not Found\n")
        quit()
    return

def doc_read(file_name): # Reads all data from a specified file and finds matches based on regular expression
    try:
        with open (file_name, 'r') as file:
            read_file = file.read()
            read_file = read_file.replace('[.]', '.') # assist in defanging the via []'s, removes the brackets for defanging.
            reg_iterator(read_file)
            print("\nOUTPUT SAVED TO FILE\n")
            startfile('Splunk_Output.txt')
    except FileExistsError:
        print("\nFile Does Not Exist\n")
        quit()
    return

def web_read(url): # Requests a specified webpage and extracts matches based on regular expression
    try:
        response = requests.get(url, verify=False, timeout=10)
        print(f"\nResponse received from {url}\n")
        if response.status_code != 200:
            print(f"\nRESPONSE CODE {response.status_code} - CHECK URL\n")
            raise
        response = response.text.replace('[.]', '.')    #Defang plain text, since we are time efficient threat hunters.
        reg_iterator(response)
        print("\nOUTPUT SAVED TO FILE\n")
        startfile('Splunk_Output.txt')
    except:
        print("\nError Requesting Webpage. Check Syntax\n")
        quit()
    return

def pdf_read(file_name): # Reads PDF files and sends data to regex iterator function
    try:
        with fitz.open(file_name) as f:
            text =''
            for page in f:
                text += page.get_text()
            text = text.replace('[.]', '.')
            reg_iterator(text)
            print("\nOUTPUT SAVED TO FILE\n")
            startfile('Splunk_Output.txt')
    except FileExistsError:
        print("\nFile Does Not Exist\n")
        quit()
    except:
        print("\nPDF Read Error\n")
        quit()

def reg_iterator(text):
    with open('Splunk_Output.txt', 'w') as file: # when use "w" overwrites as default
        file.write('') # overwrites nothing or zeros out. so Document is brand new, and not appending. 
    for i in regex.reg_list:
        matches = re.findall(i, text)
        if i == regex.domain_reg:
            print(len(matches))
        to_new(matches, i)
        new_list.clear()
    return

def to_new(matches, reg):
    for i in matches:            # Removes duplicate matches
        if i in new_list:
            continue
        elif i == "127.0.0.1" or "dhs.gov" in i or user_input in i:
            continue
        else:
            new_list.append(i)  # Appends matches to the global variable. 
    Splunk_Output(reg)
    return

def ip_check():
    ipcheckinput = 0  # Define a default value for ipcheck
    if len(str(regex.ip_reg)) > 0:  
        ipcheckinput = input("IP address detected, choose field name to search by. SrcIP - (1), DestIP - (2), Neither - (3). : ")
    
    if ipcheckinput == "1":
        return "SrcIP IN "  # Return the string "SrcIP"
    elif ipcheckinput == "2":
        return "DestIP IN "  # Return the string "DestIP"
    else:       
        return ""  # Return an empty string if neither condition is met
    return ipcheckinput
#print(ip_check())  - for testing

def initial_question():
    value_map = {
        '1': 'Source= ',
        '2': 'SourceType= ',
        '3': 'Index= '
    }

    userinput = input("Enter any number combo for desired Splunk fields (Source - (1), SourceType - (2), Index - (3), or 0 for None): ")
    
      # Check if the user wants to quit the function
    if "0" in userinput:
        quit()

    # Validate and process the input
    validchoices = ['1', '2', '3','0']
    organized_input = [value_map[digit] for digit in userinput if digit in validchoices] 

    # Concatenated the choices into string
    concatenated_choices = ' '.join(organized_input)
    return  concatenated_choices
#initial_question() -- testing


def set_initial_choices():
    global initial_choices  # Ensure we're modifying the global variable
    initial_choices = initial_question()  # This is where we call initial_question()
set_initial_choices()

def clear_ioc_list_clean():
  with open('Ioc_List_Clean.txt', 'w') as file: # when use "w" overwrites as default
        file.write('')
        return
clear_ioc_list_clean()

def Splunk_Output(reg): # Initially no values, references the Regex up top. 
    global initial_choices
    counter = 0
    with open('Splunk_Output.txt', 'a') as f: # "a" is for appending the file. # Append vs Write???
        if reg == regex.ip_reg:
            f.write(f"IOC RIP SCRIPT RUN @ {now.strftime('%m-%d-%y %H:%M:%S')} AGAINST {user_input}\nAlways Be Threat Hunting\n\n")

            if len(new_list) == 0:
                  f.write("----IP ADDRESS IOCs----\n\n" f'{ip_check()}'"")
            else: f.write("----IP ADDRESS IOCs----\n\n" f'{initial_choices}  {ip_check()}'" (")
        
        elif reg == regex.sha_256_reg:
            if len(new_list) == 0:
                  f.write("----SHA-256 HASH IOCs----\n\n")
            else: f.write("----SHA-256 HASH IOCs----\n\n" f'{initial_choices}'"  (")

        elif reg == regex.sha_1_reg:
            if len(new_list) == 0:
                  f.write("----SHA-1 HASH IOCs----\n\n")
            else: f.write("----SHA-1 HASH IOCs----\n\n" f'{initial_choices}'"  (")

        elif reg == regex.md5_reg:
            if len(new_list) == 0:
                  f.write("----MD-5 HASH IOCs----\n\n") 
            else: f.write("----MD-5 HASH IOCs----\n\n" f'{initial_choices}'"  (")
        
        elif reg == regex.http_reg:
            if len(new_list) == 0:
                  f.write("----URL IOCs----\n\n")
            else: f.write("----URL IOCs----\n\n" f'{initial_choices}'"  (")

        elif reg == regex.email_reg:
            if len(new_list) == 0:
                  f.write("----EMAIL IOCs----\n\n")
            else: f.write("----EMAIL IOCs----\n\n" f'{initial_choices}'"  (")

        elif reg == regex.domain_reg:
            if len(new_list) == 0:
                  f.write("----DOMAIN IOCs----\n\n")
            else: f.write("----DOMAIN IOCs----\n\n" f'{initial_choices}'"  (")

        elif reg == regex.path_file_reg:
            if len(new_list) == 0:
                  f.write("----PATH w/ FILE IOCs----\n\n")
            else: f.write("----PATH w/ FILE IOCs----\n\n" f'{initial_choices}'"  (")

        if len(new_list) == 0:    #This part just writes to a clean up version of the RAW input. 
            f.write("NONE FOUND\n\n") 
        else: 
            for k in new_list: 
                k = k.strip() 
                with open("Ioc_List_Clean.txt", 'a') as ip_list:
                    ip_list.write(f'{k}\n')
                if counter == len(new_list)-1: # -1 will give the last item in the list.
                    f.write(f'"{k}"')    
                    f.write (")")
                    f.write('\n\n')  # "Hits Enter", adds new lines for each IOC, instead having all in one long line.
                else:
                    f.write(f'"{k}", ') # writes "," for IN statements. 
                    counter=counter+1
                   # Delete if needed. example if counter > 0 then string, 
    return

def start():
    global user_input
    user_input = input("\nEnter File Name, URL, or File Path to File including File Extension :>>: ")
    if ".com" in user_input or ".gov" in user_input or ".edu" in user_input or ".org" in user_input or ".io" in user_input or ".net" in user_input or ".ch" in user_input:
        if "http" not in user_input:
            user_input = f'https://{user_input}'
        web_read(user_input)
    elif ".csv" in user_input:
        datafield = input("\nEnter CSV Data Column Name :>>: ")
        csv_read(user_input, datafield)
    elif ".txt" in user_input or ".doc" in user_input or ".docx" in user_input:
        doc_read(user_input)
    elif ".pdf" in user_input:
        pdf_read(user_input)
    else:
        print("\nFile Type Not Suppported\n")
        quit()
    return

start() # tells you the index of the starting position of a match.

# Testing URL to CISA.GOV for IOCs:
#web_read('https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a')
