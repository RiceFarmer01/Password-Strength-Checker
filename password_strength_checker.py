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

def generate_password(length=24, use_symbols=True):
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += string.punctuation

    return ''.join(random.choice(characters) for _ in range(length))

def check_password_strength(*args):
    password = password_var.get()
    entropy = calculate_entropy(password)
    strength = password_strength(entropy)
    result_var.set(f"Entropy: {entropy:.2f}\nStrength: {strength}")

def set_random_password():
    length = int(length_var.get())
    use_symbols = symbols_var.get()

    strong_password = generate_password(length=length, use_symbols=use_symbols)
    password_var.set(strong_password)
    check_password_strength()

def open_link(event):
    webbrowser.open_new("https://github.com/RiceFarmer01")

root = tk.Tk()
root.title("Password Strength Checker")
root.configure(bg='#333333')

style = ttk.Style()
style.configure('Custom.TFrame', background='#333333')
style.configure('Custom.TLabel', background='#333333', foreground='white')
style.configure('Custom.TCheckbutton', background='#333333', foreground='white')
style.configure("Custom.TEntry", fieldbackground="#555555", foreground="white", bordercolor="#555555", darkcolor="#555555", lightcolor="#555555", relief="flat")
style.configure("TButton", background="#555555", foreground="white")
style.map("TButton",
          background=[('active', '#666666'), ('pressed', '!disabled', '#444444')],
          relief=[('pressed', 'sunken'), ('!disabled', 'raised')],
          bordercolor=[('!disabled', '#555555')])


mainframe = ttk.Frame(root, padding="10", style='Custom.TFrame')
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

password_label = ttk.Label(mainframe, text="Enter your password:", style='Custom.TLabel')
password_label.grid(column=1, row=1, sticky=(tk.W, tk.E), padx=(0, 5))
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
mixed_case_var = tk.BooleanVar(value=True)

symbols_check = ttk.Checkbutton(mainframe, text="Use Symbols", variable=symbols_var, onvalue=True, offvalue=False, style='Custom.TCheckbutton')
symbols_check.grid(column=3, row=2, padx=(10, 0), sticky=(tk.W, tk.E))

mixed_case_check = ttk.Checkbutton(mainframe, text="Mixed Case", variable=mixed_case_var, onvalue=True, offvalue=False, style='Custom.TCheckbutton')
mixed_case_check.grid(column=4, row=2, padx=(10, 0), sticky=(tk.W, tk.E))

generate_button = ttk.Button(mainframe, text="Generate Password", command=set_random_password, style="Custom.TButton")
generate_button.grid(column=5, row=2, padx=(10, 0), sticky=(tk.W, tk.E))
result_var = tk.StringVar()
result_label = ttk.Label(mainframe, textvariable=result_var, style='Custom.TLabel')
result_label.grid(column=1, row=3, columnspan=6, sticky=(tk.W, tk.E), pady=(10, 0))

bottom_frame = ttk.Frame(root, style='Custom.TFrame')
bottom_frame.grid(column=0, row=1, sticky=(tk.W, tk.E, tk.S))

made_by_label = tk.Label(bottom_frame, text="Made by jaiden", font=("TkDefaultFont", 10), fg="white", bg="#333333")
made_by_label.pack(side="left", padx=10, pady=10)
made_by_label.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/RiceFarmer01"))

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
bottom_frame.columnconfigure(0, weight=1)

root.mainloop()