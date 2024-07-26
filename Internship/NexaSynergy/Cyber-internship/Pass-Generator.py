import random
import string
import math
import secrets
from collections import Counter
import tkinter as tk
from tkinter import ttk, messagebox

# Function to calculate password entropy
def calculate_entropy(password):
    if not password:
        return 0, 'Password is empty.'
    
    probability = Counter(password)
    length = len(password)
    entropy = -sum(freq / length * math.log2(freq / length) for freq in probability.values())
    
    if entropy < 3:
        return 'Weak', 'Entropy is too low.'
    elif 3 <= entropy < 4:
        return 'Medium', 'Entropy could be higher.'
    else:
        return 'Strong', ''

# Function to generate a random password
def generate_password(length, use_upper, use_lower, use_digits, use_special, phrase):
    chars = ''
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += string.punctuation
    
    if not chars:
        messagebox.showerror("Input Error", "Please select at least one character type.")
        return ''
    
    if phrase:
        password = phrase
        remaining_length = length - len(phrase)
    else:
        password = ''
        remaining_length = length
    
    # Ensure that we add at least one character from each selected character type
    if use_upper:
        password += secrets.choice(string.ascii_uppercase)
    if use_lower:
        password += secrets.choice(string.ascii_lowercase)
    if use_digits:
        password += secrets.choice(string.digits)
    if use_special:
        password += secrets.choice(string.punctuation)
    
    # Fill the rest of the password length
    if remaining_length > 0:
        password += ''.join(secrets.choice(chars) for _ in range(remaining_length))
    
    # Shuffle to avoid predictable patterns
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)

# Function to generate and evaluate the password
def create_password():
    try:
        length = int(length_entry.get())
    except ValueError:
        messagebox.showerror("Input Error", "Please enter a valid number for the length.")
        return
    
    use_upper = upper_var.get()
    use_lower = lower_var.get()
    use_digits = digit_var.get()
    use_special = special_var.get()
    phrase = phrase_entry.get()
    
    min_entropy = 4.0  # Minimum entropy threshold
    min_additional_length = 5  # Number of additional characters to add if needed

    if phrase and len(phrase) > length:
        messagebox.showerror("Input Error", "Phrase length exceeds the total password length.")
        return
    
    password = generate_password(length, use_upper, use_lower, use_digits, use_special, phrase)
    
    if not password:
        return
    
    # Check entropy and length
    entropy, feedback = calculate_entropy(password)
    
    if entropy == 'Weak' or len(password) < length or (entropy == 'Medium' and len(password) < length):
        response = messagebox.askyesno(
            "Enhance Password",
            f"The generated password has low entropy or does not meet the required length. "
            f"Would you like to add {min_additional_length} more characters to improve its strength?"
        )
        if response:
            length += min_additional_length
            password = generate_password(length, use_upper, use_lower, use_digits, use_special, phrase)
            entropy, feedback = calculate_entropy(password)
        else:
            if entropy == 'Weak' and len(password) < length:
                entropy_message.set(f"Entropy: {entropy} ({feedback}) - Consider improving the password.")
            else:
                entropy_message.set(f"Entropy: {entropy} ({feedback})")
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)
            if entropy == 'Weak':
                strength_message.set("Password Strength: Weak")
            elif entropy == 'Medium':
                strength_message.set("Password Strength: Medium")
            else:
                strength_message.set("Password Strength: Strong")
            return
    
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    entropy_message.set(f"Entropy: {entropy} ({feedback})")
    
    if entropy == 'Weak':
        strength_message.set("Password Strength: Weak")
    elif entropy == 'Medium':
        strength_message.set("Password Strength: Medium")
    else:
        strength_message.set("Password Strength: Strong")

# Creating the main window
root = tk.Tk()
root.title("Secure Password Generator")
root.geometry("500x400")
root.resizable(False, False)

# Styling
style = ttk.Style()
style.configure("TLabel", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TEntry", font=("Arial", 12))
style.configure("TCheckbutton", font=("Arial", 12))

# Main Frame
main_frame = ttk.Frame(root, padding="20")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Length Entry
ttk.Label(main_frame, text="Password Length:").grid(row=0, column=0, pady=5, sticky=tk.W)
length_entry = ttk.Entry(main_frame)
length_entry.grid(row=0, column=1, pady=5, sticky=tk.W)

# Phrase Entry
ttk.Label(main_frame, text="Include Phrase (optional):").grid(row=1, column=0, pady=5, sticky=tk.W)
phrase_entry = ttk.Entry(main_frame)
phrase_entry.grid(row=1, column=1, pady=5, sticky=tk.W)

# Checkbuttons for character types
upper_var = tk.BooleanVar()
lower_var = tk.BooleanVar()
digit_var = tk.BooleanVar()
special_var = tk.BooleanVar()

ttk.Checkbutton(main_frame, text="Include Uppercase Letters", variable=upper_var).grid(row=2, column=0, pady=5, sticky=tk.W)
ttk.Checkbutton(main_frame, text="Include Lowercase Letters", variable=lower_var).grid(row=2, column=1, pady=5, sticky=tk.W)
ttk.Checkbutton(main_frame, text="Include Digits", variable=digit_var).grid(row=3, column=0, pady=5, sticky=tk.W)
ttk.Checkbutton(main_frame, text="Include Special Characters", variable=special_var).grid(row=3, column=1, pady=5, sticky=tk.W)

# Generate Button
generate_button = ttk.Button(main_frame, text="Generate Password", command=create_password)
generate_button.grid(row=4, column=0, columnspan=2, pady=10)

# Password Entry
ttk.Label(main_frame, text="Generated Password:").grid(row=5, column=0, pady=5, sticky=tk.W)
password_entry = ttk.Entry(main_frame, width=30)
password_entry.grid(row=5, column=1, pady=5, sticky=tk.W)

# Entropy and Strength Messages
entropy_message = tk.StringVar()
ttk.Label(main_frame, textvariable=entropy_message, foreground="blue").grid(row=6, column=0, columnspan=2, pady=5)

strength_message = tk.StringVar()
ttk.Label(main_frame, textvariable=strength_message, foreground="blue").grid(row=7, column=0, columnspan=2, pady=5)

# Running the Tkinter event loop
root.mainloop()
