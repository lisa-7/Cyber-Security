import re
import math
import random
import string
from collections import Counter
import tkinter as tk
from tkinter import messagebox

# Function to check password length
def check_length(password):
    length = len(password)
    if length < 6:
        return 'Weak', 0, 'Password is too short (less than 6 characters).'
    elif 6 <= length < 12:
        return 'Medium', 1, 'Password could be longer (12+ characters recommended).'
    else:
        return 'Strong', 2, ''

# Function to check password complexity
def check_complexity(password):
    categories = [
        (r'[A-Z]', 'uppercase letter'),
        (r'[a-z]', 'lowercase letter'),
        (r'\d', 'digit'),
        (r'\W', 'special character')
    ]
    complexity_score = sum(bool(re.search(cat, password)) for cat, _ in categories)
    missing_elements = [desc for cat, desc in categories if not re.search(cat, password)]
    
    if complexity_score == 1:
        return 'Weak', 0, f'Missing elements: {", ".join(missing_elements)}'
    elif complexity_score == 2:
        return 'Medium', 1, f'Missing elements: {", ".join(missing_elements)}'
    else:
        return 'Strong', 2, ''

# Function to calculate password entropy
def calculate_entropy(password):
    if not password:
        return 0, 'Password is empty.'
    
    probability = Counter(password)
    length = len(password)
    entropy = -sum(freq / length * math.log2(freq / length) for freq in probability.values())
    
    if entropy < 3:
        return 'Weak', 0, 'Entropy is too low.'
    elif 3 <= entropy < 4:
        return 'Medium', 1, 'Entropy could be higher.'
    else:
        return 'Strong', 2, ''

# Function to evaluate password strength
def evaluate_password(password):
    length_result, length_score, length_feedback = check_length(password)
    complexity_result, complexity_score, complexity_feedback = check_complexity(password)
    entropy_result, entropy_score, entropy_feedback = calculate_entropy(password)
    
    overall_score = length_score + complexity_score + entropy_score
    if overall_score <= 2:
        overall_result = 'Weak'
    elif 3 <= overall_score <= 4:
        overall_result = 'Medium'
    else:
        overall_result = 'Strong'
    
    feedback = []
    if length_feedback:
        feedback.append(length_feedback)
    if complexity_feedback:
        feedback.append(complexity_feedback)
    if entropy_feedback:
        feedback.append(entropy_feedback)
    
    return {
        'Length': length_result,
        'Complexity': complexity_result,
        'Entropy': entropy_result,
        'Overall': overall_result,
        'Feedback': ' '.join(feedback) if feedback else 'Your password is strong.'
    }

# Function to suggest a strong password with required character types
def suggest_password():
    length = random.randint(12, 16)
    chars = string.ascii_letters + string.digits + string.punctuation
    password = [
        random.choice(string.ascii_lowercase),     # Ensure at least one lowercase
        random.choice(string.ascii_uppercase),     # Ensure at least one uppercase
        random.choice(string.digits),              # Ensure at least one digit
        random.choice(string.punctuation)          # Ensure at least one special character
    ]
    password += random.choices(chars, k=length-4)
    random.shuffle(password)
    return ''.join(password)

# Function to evaluate the entered password and display the result
def check_password():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Input Error", "Please enter a password.")
        return
    
    result = evaluate_password(password)
    message = (f"Length: {result['Length']}\n"
               f"Complexity: {result['Complexity']}\n"
               f"Entropy: {result['Entropy']}\n"
               f"Overall: {result['Overall']}\n"
               f"Feedback: {result['Feedback']}")
    messagebox.showinfo("Password Strength Evaluation", message)
    
    if result['Overall'] != 'Strong':
        suggested_password = suggest_password()
        suggestion_message.set(f"Suggested Strong Password: {suggested_password}")

# Creating the main window
root = tk.Tk()
root.title("Password Strength Tester")
root.geometry("400x200")
root.resizable(False, False)

# Creating and placing widgets
tk.Label(root, text="Enter your password:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(root, show='*', width=30, font=("Arial", 12))
password_entry.pack(pady=10)

check_button = tk.Button(root, text="Check Password Strength", command=check_password, font=("Arial", 12))
check_button.pack(pady=10)

# Label for showing password suggestion
suggestion_message = tk.StringVar()
suggestion_label = tk.Label(root, textvariable=suggestion_message, font=("Arial", 10), fg="blue")
suggestion_label.pack(pady=10)

# Running the Tkinter event loop
root.mainloop()
