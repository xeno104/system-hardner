import subprocess
import sys

packages = [
    "PyYAML>=6.0",
    "reportlab>=4.0"
    "fpdf>=1.7.2",
]

for package in packages:
    try:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package}. Error: {e}")

print("\n✅ All dependencies have been installed (or were already installed).")
