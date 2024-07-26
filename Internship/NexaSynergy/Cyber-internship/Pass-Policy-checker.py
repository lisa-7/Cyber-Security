import tkinter as tk
from tkinter import ttk, messagebox
import re
import os
import pickle

# File path for storing password history
HISTORY_FILE = "password_history.pkl"

class PasswordPolicy:
    def __init__(self, min_length, require_upper, require_lower, require_digit, require_special, history_limit):
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special
        self.history_limit = history_limit
        self.password_history = self.load_history()
    
    def validate_password(self, password):
        errors = []
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long.")
        if self.require_upper and not re.search(r'[A-Z]', password):
            errors.append("Password must include at least one uppercase letter.")
        if self.require_lower and not re.search(r'[a-z]', password):
            errors.append("Password must include at least one lowercase letter.")
        if self.require_digit and not re.search(r'[0-9]', password):
            errors.append("Password must include at least one digit.")
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must include at least one special character.")
        if password in self.password_history:
            errors.append("Password cannot be one of the previously used passwords.")
        return errors
    
    def add_to_history(self, password):
        if len(self.password_history) >= self.history_limit:
            self.password_history.pop(0)  # Remove the oldest password from history
        self.password_history.append(password)
        self.save_history()
    
    def save_history(self):
        with open(HISTORY_FILE, 'wb') as f:
            pickle.dump(self.password_history, f)
    
    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'rb') as f:
                return pickle.load(f)
        else:
            return []

# Function to check password compliance
def check_password():
    password = password_entry.get()
    errors = policy.validate_password(password)
    
    if errors:
        feedback = "\n".join(errors)
        messagebox.showwarning("Password Compliance Check", feedback)
    else:
        policy.add_to_history(password)
        messagebox.showinfo("Password Compliance Check", "Password meets all policies!")

# Creating the main window
root = tk.Tk()
root.title("Password Policy Checker")
root.geometry("500x300")
root.resizable(False, False)

# Styling
style = ttk.Style()
style.configure("TLabel", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TEntry", font=("Arial", 12))

# Main Frame
main_frame = ttk.Frame(root, padding="20")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Policy Configuration
ttk.Label(main_frame, text="Minimum Length:").grid(row=0, column=0, pady=5, sticky=tk.W)
min_length_entry = ttk.Entry(main_frame)
min_length_entry.grid(row=0, column=1, pady=5, sticky=tk.W)

ttk.Label(main_frame, text="Require Uppercase:").grid(row=1, column=0, pady=5, sticky=tk.W)
require_upper = tk.BooleanVar()
upper_check = ttk.Checkbutton(main_frame, variable=require_upper)
upper_check.grid(row=1, column=1, pady=5, sticky=tk.W)

ttk.Label(main_frame, text="Require Lowercase:").grid(row=2, column=0, pady=5, sticky=tk.W)
require_lower = tk.BooleanVar()
lower_check = ttk.Checkbutton(main_frame, variable=require_lower)
lower_check.grid(row=2, column=1, pady=5, sticky=tk.W)

ttk.Label(main_frame, text="Require Digit:").grid(row=3, column=0, pady=5, sticky=tk.W)
require_digit = tk.BooleanVar()
digit_check = ttk.Checkbutton(main_frame, variable=require_digit)
digit_check.grid(row=3, column=1, pady=5, sticky=tk.W)

ttk.Label(main_frame, text="Require Special Character:").grid(row=4, column=0, pady=5, sticky=tk.W)
require_special = tk.BooleanVar()
special_check = ttk.Checkbutton(main_frame, variable=require_special)
special_check.grid(row=4, column=1, pady=5, sticky=tk.W)

ttk.Label(main_frame, text="Password History Limit:").grid(row=5, column=0, pady=5, sticky=tk.W)
history_limit_entry = ttk.Entry(main_frame)
history_limit_entry.grid(row=5, column=1, pady=5, sticky=tk.W)

# Password Entry
ttk.Label(main_frame, text="Enter Password:").grid(row=6, column=0, pady=5, sticky=tk.W)
password_entry = ttk.Entry(main_frame, show='*')
password_entry.grid(row=6, column=1, pady=5, sticky=tk.W)

# Check Password Button
check_button = ttk.Button(main_frame, text="Check Password", command=lambda: set_policy_and_check())
check_button.grid(row=7, column=0, columnspan=2, pady=10)

# Policy and Check Function
def set_policy_and_check():
    try:
        min_length = int(min_length_entry.get())
        history_limit = int(history_limit_entry.get())
    except ValueError:
        messagebox.showerror("Input Error", "Please enter valid numbers for length and history limit.")
        return
    
    global policy
    policy = PasswordPolicy(
        min_length,
        require_upper.get(),
        require_lower.get(),
        require_digit.get(),
        require_special.get(),
        history_limit
    )
    
    check_password()

# Initialize policy object
policy = None

# Running the Tkinter event loop
root.mainloop()
