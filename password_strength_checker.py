import math
import random
import string
import tkinter as tk
from tkinter import ttk
import webbrowser

def calculate_entropy(password):
    char_set = set(password)
    entropy = math.log2(len(char_set)) * len(password)
    return entropy

def password_strength(entropy):
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"

def generate_password(length=24, use_symbols=True, use_mixed_case=True):
    characters = string.ascii_lowercase
    if use_mixed_case:
        characters += string.ascii_uppercase
    characters += string.digits
    if use_symbols:
        characters += string.punctuation

    return ''.join(random.choice(characters) for _ in range(length))

def check_password_strength(*args):
    password = password_var.get()
    entropy = calculate_entropy(password)
    strength = password_strength(entropy)
    crack_time = estimate_crack_time(entropy)
    result_var.set(f"Entropy: {entropy:.2f}\nStrength: {strength}\n{crack_time}")

def set_random_password():
    length = int(length_var.get())
    use_symbols = symbols_var.get()
    use_mixed_case = mixed_case_var.get()

    strong_password = generate_password(length=length, use_symbols=use_symbols, use_mixed_case=use_mixed_case)
    password_var.set(strong_password)
    check_password_strength()

def estimate_crack_time(entropy):
    crack_time = 2 ** entropy / (10 ** 9)
    units = ["seconds", "minutes", "hours", "days", "years", "centuries"]
    unit_index = 0
    while crack_time >= 60 and unit_index < len(units) - 1:
        crack_time /= 60
        unit_index += 1
    unit = units[unit_index]
    return f"Estimated time to crack: {crack_time:.2f} {unit}"

root = tk.Tk()
root.title("Password Strength Checker")
root.configure(bg='#333333')

style = ttk.Style()
style.theme_use('clam')
style.configure('Custom.TFrame', background='#333333')
style.configure('Custom.TLabel', background='#333333', foreground='white')
style.configure('Custom.TCheckbutton', background='#333333', foreground='white')
style.configure("Custom.TEntry", fieldbackground="#555555", foreground="white", bordercolor="#555555", darkcolor="#555555", lightcolor="#555555", relief="flat")

style.configure("Custom.TButton", relief="flat", borderwidth=1, background="#555555", foreground="white")
style.map("Custom.TButton",
          background=[('!disabled', '#555555'), ('active', '#666666'), ('pressed', '#444444')],
          foreground=[('!disabled', 'white')],
          relief=[('!disabled', 'flat'), ('pressed', 'sunken')])

mainframe = ttk.Frame(root, padding="10", style='Custom.TFrame')
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

password_label = ttk.Label(mainframe, text="Enter your password:", style='Custom.TLabel')
password_label.grid(column=1, row=1, sticky=(tk.W, tk.W), padx=(0, 5))
password_var = tk.StringVar()
password_var.trace("w", check_password_strength)
password_entry = ttk.Entry(mainframe, textvariable=password_var, font=("TkDefaultFont", 16), width=40, style="Custom.TEntry")
password_entry.grid(column=2, row=1, sticky=(tk.W, tk.E), columnspan=5)

length_label = ttk.Label(mainframe, text="Character Limit:", style='Custom.TLabel')
length_label.grid(column=1, row=2, sticky=(tk.W, tk.E), padx=(0, 5))
length_var = tk.StringVar(value='24')
length_entry = ttk.Entry(mainframe, textvariable=length_var, width=5, style="Custom.TEntry")
length_entry.grid(column=2, row=2, sticky=(tk.W, tk.E))

symbols_var = tk.BooleanVar(value=True)
symbols_check = ttk.Checkbutton(mainframe, text="Use Symbols", variable=symbols_var, onvalue=True, offvalue=False, style='Custom.TCheckbutton')
symbols_check.grid(column=3, row=2, padx=(10, 0), sticky=(tk.W, tk.E))

mixed_case_var = tk.BooleanVar(value=True)
mixed_case_check = ttk.Checkbutton(mainframe, text="Mixed Case", variable=mixed_case_var, onvalue=True, offvalue=False, style='Custom.TCheckbutton')
mixed_case_check.grid(column=4, row=2, padx=(10, 0), sticky=(tk.W, tk.E))

generate_button = ttk.Button(mainframe, text="Generate Password", command=set_random_password, style="Custom.TButton")
generate_button.grid(column=5, row=2, padx=(10, 0), sticky=(tk.W, tk.E))

result_var = tk.StringVar()
result_label = ttk.Label(mainframe, textvariable=result_var, style='Custom.TLabel')
result_label.grid(column=1, row=3, columnspan=6, sticky=(tk.W, tk.E))

footer_frame = ttk.Frame(root, padding="5", style='Custom.TFrame')
footer_frame.grid(column=0, row=1, sticky=(tk.W, tk.E))

made_by_label_text = f"Made by jaiden"
made_by_label = tk.Label(footer_frame, text=made_by_label_text, fg='white', bg='#333333')
made_by_label.grid(column=0, row=0, sticky=(tk.W))
made_by_label.bind("<Button-1>", lambda e: webbrowser.open_new(github_url))
made_by_label.bind("<Enter>", lambda e: made_by_label.config(fg='yellow'))
made_by_label.bind("<Leave>", lambda e: made_by_label.config(fg='white'))
github_url = "https://github.com/RiceFarmer01"
jaiden_link_text = f"jaiden"
made_by_label_text = f"Made by {jaiden_link_text} ({github_url})"
made_by_label.configure(text=made_by_label_text)

def open_github(event):
    webbrowser.open_new(github_url)

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)
mainframe.columnconfigure(2, weight=3)
mainframe.columnconfigure(3, weight=1)
mainframe.columnconfigure(4, weight=1)
mainframe.columnconfigure(5, weight=1)
mainframe.columnconfigure(6, weight=1)
mainframe.rowconfigure(1, weight=1)
mainframe.rowconfigure(2, weight=1)

root.mainloop()