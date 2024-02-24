# Splunk_IOC_Ripper

## Introduction
Splunk_IOC_Ripper is a powerful Python tool designed to streamline the process of identifying and extracting Indicators of Compromise (IOCs) from a variety of sources. With an ability to handle even the most unstructured and cluttered data, it automatically parses and categorizes IOCs such as SHA-256 hashes, MD-5 hashes, IP addresses, URLs, domains, and emails into a clean, user-friendly format. This makes it an invaluable resource for cybersecurity analysts and enthusiasts looking to enhance their Splunk data analysis workflows.

## Features
- **Automatic Parsing:** Effortlessly extract IOCs from a chaotic mix of text and non-IOC alphanumeric characters.
- **Support for Multiple Sources:** Process IOCs from plain text files, CSVs, PDFs, and URLs with ease.
- **User-Friendly Outputs:** Generate organized lists of IOCs suitable for immediate use in Splunk.
- **Flexible Input Handling:** Accepts raw data input through text files, allowing for quick copy-paste operations.
- **Secure URL Processing:** Automatically converts HTTP URLs to HTTPS for enhanced security.

## How to Use
1. **Text File Input (IOCs_Raw.txt):**
   - Copy and paste any mixed content (IOCs and non-IOC text) into `IOCs_Raw.txt` or any text file of your choice. The program will process and organize the IOCs for you.

2. **CSV/PDF Files:**
   - The tool scans and parses entire CSV or PDF files for IOCs. If the file is not in the current directory, provide the full path, including the file extension.

3. **URLs:**
   - Simply paste the URL when prompted by the program. It will automatically adjust protocols from HTTP to HTTPS.

## Output Files
- **Splunk_Output.txt:** This is the primary output file where the processed IOCs are saved. Do not rename or move this file.
- **Ioc_List_Clean.txt:** Contains a clean, unformatted list of the IOCs you've provided. Do not rename or move this file.
- **IOCs_Raw.txt:** Initially loaded with your unorganized mix of IOCs and raw text. This is a placeholder and can be renamed if necessary.

## Note
The code is heavily commented to provide both explanation for users and personal reference. This ensures clarity in understanding the program's functionality and ease of use.


