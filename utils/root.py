import os
import sys
import ctypes

def is_windows_admin() -> bool:
  
    if os.name != "nt":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def request_windows_admin(exit_after_request: bool = True) -> bool:

    if os.name != "nt":
        return False

    if is_windows_admin():
        return True

    python_exe = sys.executable
 
    if python_exe.lower().endswith("python.exe"):
        python_exe = python_exe[:-10] + "pythonw.exe"

    script_or_exe = os.path.abspath(sys.argv[0])
    args = [script_or_exe] + sys.argv[1:]
    params = " ".join(f'"{a}"' for a in args)

    try:
        
        res = ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params, None, 1)
        success = int(res) > 32
        if not success:
            return False
        if exit_after_request:
            sys.exit(0)  
        return False
    except Exception:
        return False


