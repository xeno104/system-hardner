import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from threading import Thread
import os
import sys
from datetime import datetime
import subprocess
from fpdf import FPDF
# Local Packages
from utils.generate_audit_report import generate_report
from utils.os_detect import detect_os
from utils.policy_manager import load_policy
from utils.audit import audit_policy
from utils.root import is_windows_admin, request_windows_admin
from utils.remediation import remediate_all_rules
from utils.snapshot import snapshot_all_rules
from utils.rollback import rollback_all_rules
from utils.logger import setup_logger





# Initialize logger
logger = setup_logger("SystemHardener")
logger.info("Starting System Hardener UI...")

root = tk.Tk()
try:
    icon_path = os.path.join("assets", "app_icon.png")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
        logger.info("Application icon set successfully.")
    else:
        logger.warning(f"App icon not found at: {icon_path}")
except Exception as e:
    logger.error(f"Failed to set app icon: {e}")



# Detect OS
os_name, os_version = detect_os()
logger.info(f"Detected OS: {os_name} {os_version}")

config = {
    "policy_path": (
        "policy/policy_windows.yaml" if os_name == "windows" else
        "policy/policy_ubuntu.yaml" if os_name == "ubuntu" else
        "policy/policy_centos.yaml"
    ),
    "os": os_name,
    "os_version": os_version,
    "current_level": "Basic"
}




# Check - Supporting Operating System
logger.info(f"Checking OS compatibility: {os_name}")

if os_name not in ["windows", "ubuntu", "centos"]:
    root.withdraw()
    messagebox.showerror(
        "Unsupported OS",
        "System Hardener is currently in beta and only supported on Windows, Ubuntu, and CentOS."
    )
    logger.error(f"Unsupported OS detected: {os_name}")
    sys.exit(0)

logger.info(f"Operating system '{os_name}' is supported.")

# ------------------ Requesting - Root/Admin Privilege ------------------
logger.info("Checking for administrative/root privileges...")

try:
    if os_name == "windows":
        if not is_windows_admin():
            logger.warning("Admin privileges not detected. Attempting to request elevation...")
            if not request_windows_admin(exit_after_request=True):
                logger.error("User declined admin privilege request. Exiting.")
                sys.exit(1)
            else:
                logger.info("Privilege escalation requested successfully.")
        else:
            logger.info("Admin privileges confirmed.")
    else:
      
        if os.geteuid() != 0:
            logger.warning("Root privileges not detected. Attempting pkexec elevation...")

            py = sys.executable
            script = os.path.abspath(sys.argv[0])
            display = os.environ.get("DISPLAY", ":0")
            xauth = os.environ.get("XAUTHORITY", "")

            cmd = ["pkexec", "env", f"DISPLAY={display}"]
            if xauth:
                cmd.append(f"XAUTHORITY={xauth}")
            cmd += [py, script] + sys.argv[1:]

            try:
                logger.debug(f"Executing privilege elevation command: {' '.join(cmd)}")
                subprocess.check_call(cmd)
                logger.info("Privilege escalation successful via pkexec.")
                sys.exit(0)
            except subprocess.CalledProcessError as e:
                logger.error(f"Privilege escalation failed: {e}")
                messagebox.showerror("Permission Error", "Root privileges are required to continue.")
                sys.exit(1)
        else:
            logger.info("Root privileges confirmed.")
except Exception as e:
    logger.exception(f"Error while checking or requesting privileges: {e}")
    messagebox.showerror("Privilege Error", f"Unexpected error while checking privileges:\n{e}")
    sys.exit(1)


  



# Load policy
logger.info(f"Loading policy file: {config['policy_path']}")
policy = load_policy(config["policy_path"])

if not policy:
    logger.error("Policy is invalid or missing!")
    messagebox.showerror("Error", "Policy is not valid")
    sys.exit(1)

logger.info("Policy loaded successfully.")



root.title("System Hardener")
root.geometry("900x600")
root.configure(bg="#1e1e1e")

    
logger.info("Main UI initialized.")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Sidebar
sidebar_bg = "#808080"
sidebar_fg = "#ffffff"
sidebar = tk.Frame(root, width=200, bg=sidebar_bg)
sidebar.grid(row=0, column=0, sticky="ns")
sidebar.grid_propagate(False)

os_label = tk.Label(
    sidebar, 
    text=f"{config['os'].capitalize()} {os_version} Detected", 
    bg=sidebar_bg, fg=sidebar_fg,
    font=("Arial", 10, "bold"),
    justify="center"
)
os_label.pack(pady=20, padx=10)

# Main content
main_bg = "#1e1e1e"
main_content = tk.Frame(root, bg=main_bg)
main_content.grid(row=0, column=1, sticky="nsew")

top_bar = tk.Frame(main_content, bg=main_bg)
top_bar.pack(fill="x", padx=10, pady=10)

status_text = "Policy Loaded" if policy else "Policy Not Loaded"
status_color = "#2ecc71" if policy else "#e74c3c"

policy_status_label = tk.Label(
    top_bar,
    text=status_text,
    font=("Arial", 12, "bold"),
    bg=main_bg,
    fg=status_color,
)
policy_status_label.pack(side="right", padx=(0, 10))

level = tk.Label(
    top_bar,
    text="Level:",
    font=("Arial", 12, "bold"),
    bg=main_bg,
    fg="#ffffff",
)
level.pack(side="left", padx=(0, 10))

# Combobox
combo = ttk.Combobox(
    top_bar,
    values=["Basic", "Moderate", "Strict"],
    state="readonly"
)
combo.current(0)
combo.pack(side="left")

def on_dropdown_change(event=None):
    selected_value = combo.get()
    config["current_level"] = selected_value
    logger.info(f"🔄 Config updated → current_level = {config['current_level']}")
    logger.info("Refreshing audit results due to level change...")
    show_audit_results()

combo.bind("<<ComboboxSelected>>", on_dropdown_change)

main_label = tk.Label(
    main_content,
    text="Audit Dashboard",
    font=("Arial", 12, "bold"),
    bg=main_bg,
    fg="white"
)
main_label.pack(pady=10)

results_frame = tk.Frame(main_content, bg=main_bg)
results_frame.pack(fill="both", expand=True, padx=10, pady=10)


def show_audit_results():
    logger.info("Refreshing audit results on UI...")

    # Clear previous results
    for widget in results_frame.winfo_children():
        widget.destroy()

    # ------------------ Show "Loading..." Text ------------------
    loading_label = tk.Label(
        results_frame,
        text="Loading...",
        bg=main_bg,
        fg="white",
        font=("Arial", 14, "bold")
    )
    loading_label.pack(expand=True, pady=20)

    # Run audit in background to keep UI responsive
    def run_audit():
        try:
            audit_results = audit_policy(policy, config["current_level"])
            logger.info(f"Audit complete with {len(audit_results)} results at level {config['current_level']}")

            def update_ui():
                # Clear "Loading..." message
                for widget in results_frame.winfo_children():
                    widget.destroy()

                tk.Label(
                    results_frame, text="Title", bg=main_bg, fg="white",
                    font=("Arial", 11, "bold"), width=60, anchor="w"
                ).grid(row=0, column=0, padx=5, pady=2)

                tk.Label(
                    results_frame, text="Status", bg=main_bg, fg="white",
                    font=("Arial", 11, "bold"), width=15, anchor="w"
                ).grid(row=0, column=1, padx=5, pady=2)

                for i, (rule_id, status) in enumerate(audit_results, start=1):
                    rule_title = next(
                        (r.get("title", "") for r in policy.get("rules", []) if r.get("id") == rule_id),
                        ""
                    )

                    tk.Label(
                        results_frame, text=rule_title, bg=main_bg, fg="white",
                        font=("Arial", 11), anchor="w"
                    ).grid(row=i, column=0, sticky="w", padx=5, pady=1)

                    if status.lower() == "compliant":
                        icon, color = "✅", "green"
                    elif status.lower() == "non-compliant":
                        icon, color = "❌", "red"
                    else:
                        icon, color = "⚪", "white"

                    tk.Label(
                        results_frame, text=f"{icon} {status}", bg=main_bg, fg=color,
                        font=("Arial", 11), anchor="w"
                    ).grid(row=i, column=1, sticky="w", padx=5, pady=1)

            root.after(0, update_ui)
        except Exception as e:
            logger.exception(f"Error during audit execution: {e}")
            messagebox.showerror("Error", f"An error occurred while auditing:\n{e}")

    Thread(target=run_audit).start()


def run_with_loading(func, message="Processing..."):
  
    logger.info(f"Starting background task: {message}")
    
    for widget in root.winfo_children():
        try:
            widget.configure(state='disabled')
        except Exception:
            pass

    loading = tk.Toplevel(root)
    loading.title("Please wait")
    loading.geometry("300x100")
    loading_label = tk.Label(loading, text=message)
    loading_label.pack(expand=True, fill='both', padx=10, pady=20)
    loading.update()

    def task():
        try:
            func()
            logger.info(f"Task '{message}' completed successfully.")
        except Exception as e:
            logger.exception(f"Error during '{message}': {e}")
        finally:
            loading.destroy()
            for widget in root.winfo_children():
                try:
                    widget.configure(state='normal')
                except Exception:
                    pass
            

    Thread(target=task).start()


def remediation_action():
    logger.info("User clicked Remediation button.")
    run_with_loading(lambda: [
        snapshot_all_rules(policy, config["policy_path"]), 
        remediate_all_rules(policy, config["policy_path"], config["current_level"]),
        show_audit_results()
    ], message="Applying all remediations...")


def rollback_action():
    logger.info("User clicked Rollback button.")
    run_with_loading(lambda: [
        rollback_all_rules(policy, config["policy_path"]),
        show_audit_results() ],                  
                     message="Rolling back changes...")


def audit_report_action():
    logger.info("User clicked Generate Audit Report button.")
    def task():
        result = audit_policy(policy, config["current_level"])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"audit_report_{timestamp}.csv"
        generate_report(result, policy, csv_filename)
        full_path = os.path.abspath(csv_filename)
        logger.info(f"Audit report generated: {full_path}")
        messagebox.showinfo("Audit Report Generated",
                            f"The audit report has been successfully generated at:\n{full_path}")
    run_with_loading(task, message="Generating audit report...")


def log_report_action():
    logger.info("User clicked Generate Log Report button.")

    def task():
        output_dir = "reports"
        log_dir = "logs"
        os.makedirs(output_dir, exist_ok=True)

        log_files = sorted([f for f in os.listdir(log_dir) if f.endswith(".log")])
        logger.debug(f"Found log files for report: {log_files}")
        if not log_files:
            logger.warning("No log files found to generate report.")
            messagebox.showinfo("Log Report", "No log files found to generate report.")
            return

        pdf_file_path = os.path.join(output_dir, "combined_log_report.pdf")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Use core font (no TTF required)
        pdf.set_font("Courier", "", 10)

        for log_file in log_files:
            log_path = os.path.join(log_dir, log_file)
            pdf.add_page()
            pdf.set_font("Courier", "B", 12)
            pdf.cell(0, 10, f"Log File: {log_file}", ln=True)
            pdf.set_font("Courier", "", 10)

            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        # Replace non-ASCII to prevent PDF errors
                        safe_line = line.encode("latin1", errors="replace").decode("latin1")
                        pdf.multi_cell(0, 5, safe_line.rstrip())
            except Exception as e:
                logger.error(f"Failed to read log {log_file}: {e}")

        try:
            pdf.output(pdf_file_path)
            logger.info(f"Log report generated: {pdf_file_path}")
            messagebox.showinfo(
                "Log Report Generated",
                f"The log report has been successfully generated at:\n{pdf_file_path}"
            )
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            messagebox.showerror("Log Report Error", f"Failed to generate log report:\n{e}")

    run_with_loading(task, message="Generating log report...")


logger.info("Generating initial audit results...")
run_with_loading(show_audit_results, message="Generating initial audit results...")


buttons = [
    ("Remediation", remediation_action),
    ("Rollback", rollback_action),
    ("Generate Audit Report", audit_report_action),
    ("Generate Log Report", log_report_action),
]

for btn_text, btn_cmd in buttons:
    btn = tk.Button(
        sidebar, text=btn_text, width=20, pady=5,
        bg="#ffffff", fg="#000000", activebackground="#1abc9c", activeforeground="white",
        relief="flat", command=btn_cmd
    )
    btn.pack(pady=5, padx=10)

logger.info("UI fully loaded. Ready for user actions.")
root.mainloop()



