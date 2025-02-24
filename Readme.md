# 0xBBi8 Network Scanner

An advanced, multi-threaded network scanner built in Python. This tool performs a fast and efficient scan of your network, identifying active devices and retrieving their hostnames. 

## Features

✅ **Detect Public & Local IP**  
✅ **Subnet Calculation for macOS/Linux**  
✅ **Multi-threaded Scanning for Speed**  
✅ **Hostname Resolution for Online Devices**  
✅ **Custom Output File Support (-O option)**  
✅ **Minimal Dependencies**  

## Installation

### **1. Clone the Repository**
```sh
git clone https://github.com/yourusername/netscanner.git
cd netscanner
```

### **2. Install Dependencies**
Use the `requirements.txt` file to install all necessary dependencies:
```sh
pip install -r requirements.txt
```

### **3. Run the Scanner**
To execute the scanner, simply run:
```sh
python netscanner.py
```

If you want to save the scan results to a file, use:
```sh
python netscanner.py -O output.txt
```

## Usage

```sh
python netscanner.py [-O OUTPUT_PATH]
```

**Arguments:**
- `-O OUTPUT_PATH`  (Optional) Specify the file path to save the scan results.

## Example Output
```
Netscanner by 0xBBi8
--------------------------------------------------
Public IP  : 172.100.1.50
Local IP   : 192.168.1.42
Subnet     : 192.168.1.0/24
--------------------------------------------------
[+] 192.168.1.10 is online - laptop.home
[+] 192.168.1.20 is online - server.home
[+] 192.168.1.30 is online - phone.home
[+] 192.168.1.50 is online - Unknown hostname
--------------------------------------------------
[+] A total of 4 active devices were found.
```

## License
This project is licensed under the MIT License.

## Author
**0xBBi8** - Advanced Network Security Enthusiast 🔥
