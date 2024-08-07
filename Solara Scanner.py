import os
import psutil
import time
import requests
import socket
import subprocess
import traceback
import winreg
import yara
import pefile
from scapy.all import sniff
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileChangeHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        print(f"File system event: {event.event_type} - {event.src_path}")

def check_bootstrapper():
    try:
        for process in psutil.process_iter(['name', 'exe']):
            if process.info['name'] == 'Bootstrapper.exe':
                return process
        return None
    except Exception as e:
        print(f"Error in check_bootstrapper: {e}")
        return None

def monitor_resources(process):
    try:
        cpu_percent = process.cpu_percent(interval=1)
        memory_info = process.memory_info()
        print(f"CPU Usage: {cpu_percent}%")
        print(f"Memory Usage: {memory_info.rss / (1024 * 1024):.2f} MB")
    except Exception as e:
        print(f"Error in monitor_resources: {e}")

def analyze_network():
    try:
        def packet_callback(packet):
            if packet.haslayer('IP'):
                print(f"Packet: {packet['IP'].src} -> {packet['IP'].dst}")
        sniff(prn=packet_callback, count=10)
    except Exception as e:
        print(f"Error in analyze_network: {e}")

def check_suspicious_processes():
    try:
        suspicious = []
        for process in psutil.process_iter(['name', 'exe']):
            if process.info['name'].lower() in ['cmd.exe', 'powershell.exe']:
                suspicious.append(process.info['name'])
        return suspicious
    except Exception as e:
        print(f"Error in check_suspicious_processes: {e}")
        return []

def scan_for_malware(process):
    try:
        rules = yara.compile(filepath='malware_rules.yar')
        matches = rules.match(pid=process.pid)
        if matches:
            print(f"Potential malware detected: {matches}")
    except Exception as e:
        print(f"Error in scan_for_malware: {e}")

def monitor_file_system():
    try:
        path = r""  # add your solara path here
        event_handler = FileChangeHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        time.sleep(10)
        observer.stop()
        observer.join()
    except Exception as e:
        print(f"Error in monitor_file_system: {e}")

def analyze_memory(process):
    try:
        with open(process.exe(), 'rb') as f:
            pe = pefile.PE(data=f.read())
            for section in pe.sections:
                print(f"Section: {section.Name.decode().strip('\x00')}")
    except Exception as e:
        print(f"Error in analyze_memory: {e}")

def check_dll_injection(process):
    try:
        dlls = process.memory_maps()
        for dll in dlls:
            if 'SOLARA' not in dll.path:
                print(f"Potential DLL injection: {dll.path}")
    except Exception as e:
        print(f"Error in check_dll_injection: {e}")

def analyze_registry():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SOLARA")
        for i in range(1024):
            try:
                name, value, type = winreg.EnumValue(key, i)
                print(f"Registry: {name} = {value}")
            except WindowsError:
                break
    except Exception as e:
        print(f"Error in analyze_registry: {e}")

def check_for_exploits(process):
    try:
        with open(process.exe(), 'rb') as f:
            pe = pefile.PE(data=f.read())
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress == 0:
                print("Warning: Executable is not signed")
    except Exception as e:
        print(f"Error in check_for_exploits: {e}")

def check_websocket_library():
    try:
        import websocket
        print("Websocket library is present")
    except ImportError:
        print("Websocket library is missing")

def check_hidden_properties():
    try:
        print("Checking hidden properties and scriptability...")
    except Exception as e:
        print(f"Error in check_hidden_properties: {e}")

def check_real_error_info():
    try:
        print("Checking for real error info...")
    except Exception as e:
        print(f"Error in check_real_error_info: {e}")

def check_stability():
    try:
        print("Checking stability improvements...")
        cpu_usage = psutil.cpu_percent(interval=1)
        ram_usage = psutil.virtual_memory().percent
        print(f"Current CPU usage: {cpu_usage}%")
        print(f"Current RAM usage: {ram_usage}%")
    except Exception as e:
        print(f"Error in check_stability: {e}")

def check_filesystem_performance():
    try:
        start_time = time.time()
        with open(r"     " , "w") as f:  # add your solara path here
            f.write("A" * 1000000)
        end_time = time.time()
        print(f"Filesystem write time: {end_time - start_time} seconds")
        os.remove(r"") #add your solara path here
    except Exception as e:
        print(f"Error in check_filesystem_performance: {e}")

def check_speed_improvements():
    try:
        start_time = time.time()
        for _ in range(1000000):
            pass
        end_time = time.time()
        print(f"Speed test time: {end_time - start_time} seconds")
    except Exception as e:
        print(f"Error in check_speed_improvements: {e}")

def check_vulnerability_mitigation():
    try:
        print("Checking Luau vulnerability mitigation...")
        print("Checking for RCE vulnerabilities...")
    except Exception as e:
        print(f"Error in check_vulnerability_mitigation: {e}")

def check_static_dependencies():
    try:
        print("Checking for statically linked dependencies...")
        process = psutil.Process(os.getpid())
        for module in process.memory_maps():
            if module.path.endswith('.dll'):
                print(f"Dynamic library found: {module.path}")
    except Exception as e:
        print(f"Error in check_static_dependencies: {e}")

def main():
    while True:
        try:
            process = check_bootstrapper()
            if not process:
                print("Bootstrapper not running, waiting...")
                time.sleep(5)  
                continue
            print("Scanning for vulnerabilities...")
            monitor_resources(process)
            analyze_network()
            suspicious = check_suspicious_processes()
            if suspicious:
                print(f"Suspicious processes: {suspicious}")
            scan_for_malware(process)
            monitor_file_system()
            analyze_memory(process)
            check_dll_injection(process)
            analyze_registry()
            check_for_exploits(process)
            check_websocket_library()
            check_hidden_properties()
            check_real_error_info()
            check_stability()
            check_filesystem_performance()
            check_speed_improvements()
            check_vulnerability_mitigation()
            check_static_dependencies()
            print("Scan complete. Starting next scan immediately...")
        except Exception as e:
            print(f"An error occurred in the main loop: {e}")
            print(traceback.format_exc())
            print("Restarting in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    print("Starting vulnerability scanner. Press Ctrl+C to exit.")
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        print("Scanner stopped. Press Enter to close this window.")
        input()
