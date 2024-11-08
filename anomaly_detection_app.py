import tkinter as tk
from tkinter import messagebox, filedialog
from plyer import notification
import csv
import os

# Initialize global variables
failed_login_count = 0
sensitive_files_list = []

# Function to show desktop notifications
def show_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        timeout=5
    )

# Function to check credentials from CSV
def verify_credentials(username, password):
    try:
        with open("credentials.csv", mode="r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row["username"] == username and row["password"] == password:
                    return True
    except FileNotFoundError:
        messagebox.showerror("Error", "credentials.csv not found!")
    return False

# Function to load sensitive files from CSV
def load_sensitive_files():
    sensitive_files = []
    try:
        with open("sensitive_files.csv", mode="r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                sensitive_files.append(row["filename"])
        print("Sensitive files loaded:", sensitive_files)  # Debug print
    except FileNotFoundError:
        messagebox.showerror("Error", "sensitive_files.csv not found!")
    return sensitive_files

# Login button function
def login():
    global failed_login_count
    username = entry_username.get()
    password = entry_password.get()

    if verify_credentials(username, password):
        messagebox.showinfo("Login Success", f"Welcome, {username}!")
        failed_login_count = 0  # Reset failed attempts after success
        open_dashboard()
    else:
        failed_login_count += 1
        messagebox.showerror("Login Failed", "Incorrect username or password.")

        # Detect 3 failed login attempts
        if failed_login_count >= 3:
            show_notification("Anomaly Detected", "3 Failed Login Attempts Detected!")
            failed_login_count = 0  # Reset after notification

# Function to handle file sharing
def share_file():
    file_path = filedialog.askopenfilename(title="Select a file to share")

    if file_path:
        file_name = os.path.basename(file_path)
        print("File selected:", file_name)  # Debug print
        if file_name in sensitive_files_list:
            show_notification("Anomaly Detected", f"Attempt to share sensitive file '{file_name}' detected!")
            messagebox.showerror("File Sharing Blocked", f"The sensitive file '{file_name}' cannot be shared.")
        else:
            messagebox.showinfo("File Shared", f"The file '{file_name}' was shared successfully.")

# Function to open the dashboard
def open_dashboard():
    # Hide the login window
    login_window.withdraw()

    # Create the dashboard window
    dashboard = tk.Toplevel()
    dashboard.title("Employee Dashboard")
    dashboard.geometry("400x300")
    dashboard.configure(bg="#f0f0f0")

    # Dashboard Title
    title_label = tk.Label(dashboard, text="Employee Dashboard", font=("Arial", 16, "bold"), bg="#f0f0f0")
    title_label.pack(pady=20)

    # Share File Button
    share_button = tk.Button(dashboard, text="Share File", command=share_file, font=("Arial", 12), width=15, bg="#2196F3", fg="white")
    share_button.pack(pady=10)

    # Logout Button
    logout_button = tk.Button(dashboard, text="Logout", command=lambda: logout(dashboard), font=("Arial", 12), width=15, bg="#f44336", fg="white")
    logout_button.pack(pady=10)

# Function to handle logout
def logout(dashboard_window):
    dashboard_window.destroy()
    login_window.deiconify()

# Load sensitive files list
sensitive_files_list = load_sensitive_files()

# Setting up the Login UI
login_window = tk.Tk()
login_window.title("Employee Management App - Login")
login_window.geometry("400x300")
login_window.configure(bg="#2c3e50")

# UI Title
title_label = tk.Label(login_window, text="Employee Login", font=("Arial", 16, "bold"), bg="#2c3e50", fg="white")
title_label.pack(pady=20)

# Username and Password Fields
frame = tk.Frame(login_window, bg="#2c3e50")
frame.pack(pady=10)

tk.Label(frame, text="Username:", font=("Arial", 12), bg="#2c3e50", fg="white").grid(row=0, column=0, padx=5, pady=5)
entry_username = tk.Entry(frame, font=("Arial", 12))
entry_username.grid(row=0, column=1, padx=5, pady=5)

tk.Label(frame, text="Password:", font=("Arial", 12), bg="#2c3e50", fg="white").grid(row=1, column=0, padx=5, pady=5)
entry_password = tk.Entry(frame, show="*", font=("Arial", 12))
entry_password.grid(row=1, column=1, padx=5, pady=5)

# Login Button
login_button = tk.Button(login_window, text="Login", command=login, font=("Arial", 12), width=10, bg="#4CAF50", fg="white")
login_button.pack(pady=20)

# Run the application
login_window.mainloop()
