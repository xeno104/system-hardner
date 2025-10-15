import os
import sys
import platform

def detect_os():
  
    system = platform.system().lower()

    if system == "windows":
        os_name = "windows"
        try:
            build = sys.getwindowsversion().build
            if build >= 22000:
                os_version = "11"
            else:
                os_version = "10"
        except Exception:
            os_version = platform.release()

    elif system == "linux":
        os_name = "linux"
        os_version = "unknown"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("VERSION_ID="):
                        os_version = line.strip().split("=")[1].strip('"')
                        break
        except FileNotFoundError:
            pass

    else:
        os_name = system
        os_version = platform.release()

    return os_name, os_version


