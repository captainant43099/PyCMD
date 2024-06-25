import os
import readline
import atexit
import sys
import getpass
import time
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog

print("Script starting...")

# Command history file
HISTORY_FILE = os.path.expanduser("~/.pycmd_history")
USER_CREDENTIALS_FILE = os.path.expanduser("~/.pycmd_users")
DISABLED_USERS_FILE = os.path.expanduser("~/.pycmd_disabled_users")

print("Loading history if available...")

# Load history if available
if os.path.exists(HISTORY_FILE):
    readline.read_history_file(HISTORY_FILE)
    print("History loaded.")
else:
    print("No history file found.")

# Save history on exit
def save_history():
    readline.write_history_file(HISTORY_FILE)

atexit.register(save_history)

RESTRICTED_COMMANDS = [
    'taskkill', 'net user', 'shutdown', 'diskpart', 'format', 'sfc', 'chkdsk',
    'gpupdate', 'gpresult', 'regedit', 'regsvr32', 'eventvwr', 'perfmon',
    'services.msc', 'dcomcnfg', 'msconfig', 'control', 'compmgmt.msc',
    'mmc', 'secpol.msc', 'lusrmgr.msc', 'gpedit.msc', 'diskmgmt.msc', 'taskschd.msc',
    'bcdedit', 'bcdboot', 'bootrec', 'sc', 'schtasks', 'wbadmin', 'wevtutil', 'wusa',
    'icacls', 'takeown', 'manage-bde', 'defrag', 'mbr2gpt', 'reagentc', 'regini'
]

ADMIN_ONLY_COMMANDS = [
    '!pycmd delete_user', '!pycmd add_user', '!pycmd disable_user', '!pycmd reset_app', '!pycmd enable_user'
]

RESTRICTED_COMMANDS = [cmd.lower() for cmd in RESTRICTED_COMMANDS]

def load_users():
    """Load user credentials from file."""
    print("Loading users...")
    users = {}
    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    data = line.split(':')
                    username, password = data[:2]
                    additional_info = data[2:]
                    users[username] = {'password': password, 'info': additional_info}
    print("Users loaded.")
    return users

def save_users(users):
    """Save all user credentials to file."""
    print("Saving users...")
    with open(USER_CREDENTIALS_FILE, 'w') as file:
        for username, data in users.items():
            file.write(f"{username}:{data['password']}:{':'.join(data['info'])}\n")

def save_user(username, password, full_name, role):
    """Save new user credentials to file."""
    print(f"Saving user: {username}")
    with open(USER_CREDENTIALS_FILE, 'a') as file:
        file.write(f"{username}:{password}:{full_name}:{role}\n")

def load_disabled_users():
    """Load disabled users from file."""
    print("Loading disabled users...")
    disabled_users = set()
    if os.path.exists(DISABLED_USERS_FILE):
        with open(DISABLED_USERS_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    disabled_users.add(line)
    print("Disabled users loaded.")
    return disabled_users

def save_disabled_users(disabled_users):
    """Save disabled users to file."""
    print("Saving disabled users...")
    with open(DISABLED_USERS_FILE, 'w') as file:
        for username in disabled_users:
            file.write(f"{username}\n")

def register_user(users):
    """Register a new user."""
    print("Register a new user")
    username = input("Enter username: ").strip()
    if username in users:
        print("Username already exists. Try a different username.")
        return
    password = getpass.getpass("Enter password: ").strip()
    confirm_password = getpass.getpass("Confirm password: ").strip()
    if password != confirm_password:
        print("Passwords do not match. Registration failed.")
        return
    full_name = input("Enter full name: ").strip()
    role = input("Enter role (admin/basic): ").strip().lower()
    while role not in ['admin', 'basic']:
        print("Invalid role. Please enter 'admin' or 'basic'.")
        role = input("Enter role (admin/basic): ").strip().lower()

    save_user(username, password, full_name, role)
    users[username] = {'password': password, 'info': [full_name, role]}
    print("Registration successful.")

def delete_user(users):
    """Delete an existing user."""
    print("Delete a user")
    username = input("Enter username to delete: ").strip()
    if username not in users:
        print("User not found.")
        return
    confirm = input(f"Are you sure you want to delete the user '{username}'? (yes/no): ").strip().lower()
    if confirm == 'yes':
        del users[username]
        save_users(users)
        print(f"User {username} deleted successfully.")
    else:
        print("User deletion canceled.")

def change_password(users):
    """Change the password of an existing user."""
    print("Change user password")
    username = input("Enter username to change password: ").strip()
    if username not in users:
        print("User not found.")
        return
    password = getpass.getpass("Enter new password: ").strip()
    confirm_password = getpass.getpass("Confirm new password: ").strip()
    if password != confirm_password:
        print("Passwords do not match. Password change failed.")
        return
    users[username]['password'] = password
    save_users(users)
    print(f"Password for user {username} changed successfully.")

def list_users(users):
    """List all users."""
    print("List of users:")
    for username, data in users.items():
        print(f"Username: {username}, Full Name: {data['info'][0]}, Role: {data['info'][1]}")

def user_info(users, username):
    """Display information about a specific user."""
    if username not in users:
        print(f"User '{username}' not found.")
        return
    data = users[username]
    print(f"Username: {username}")
    print(f"Full Name: {data['info'][0]}")
    print(f"Role: {data['info'][1]}")

def disable_user(users, disabled_users):
    """Disable an existing user."""
    print("Disable a user")
    username = input("Enter username to disable: ").strip()
    if username not in users:
        print("User not found.")
        return
    disabled_users.add(username)
    save_disabled_users(disabled_users)
    print(f"User {username} disabled successfully.")

def enable_user(users, disabled_users):
    """Enable a previously disabled user."""
    print("Enable a user")
    username = input("Enter username to enable: ").strip()
    if username not in users:
        print("User not found.")
        return
    if username not in disabled_users:
        print("User is not disabled.")
        return
    disabled_users.remove(username)
    save_disabled_users(disabled_users)
    print(f"User {username} enabled successfully.")

def reset_app():
    """Reset the application by deleting all user and disabled user files."""
    confirm = input("Are you sure you want to reset the application? This will delete all user data. (yes/no): ").strip().lower()
    if confirm == 'yes':
        if os.path.exists(USER_CREDENTIALS_FILE):
            os.remove(USER_CREDENTIALS_FILE)
        if os.path.exists(DISABLED_USERS_FILE):
            os.remove(DISABLED_USERS_FILE)
        print("Application reset successfully.")
    else:
        print("Application reset canceled.")

def authenticate_user(users, disabled_users):
    """Authenticate an existing user."""
    print("User Login")
    username = input("Enter username: ").strip()
    if username in disabled_users:
        print("This user is disabled.")
        return None, None
    password = getpass.getpass("Enter password: ").strip()
    user_data = users.get(username)
    if user_data and user_data['password'] == password:
        print(f"Welcome, {username}!")
        return username, user_data['info'][1]  # Return username and role
    else:
        print("Invalid username or password.")
        return None, None

def show_help(role):
    """Display help information."""
    help_text = """
    PyCMD - A Python-based Command Line Interface

    Available Commands:
      help                       - Display this help message
      exit                       - Exit the PyCMD
      logout                     - Log out and return to the login prompt
      !pycmd list_users          - List all users
      !pycmd user_info <username>- Display information about a specific user
      !pycmd change_password     - Change the password of an existing user
      !pycmd calc                - Open the calculator app
      !pycmd timer               - Start a countdown timer
      !pycmd weather             - Get the current weather (mocked)
      !pycmd run <app>           - Run a DOS application
    """
    if role == 'admin':
        admin_help_text = """
      !pycmd delete_user         - Delete an existing user
      !pycmd add_user            - Add a new user
      !pycmd disable_user        - Disable an existing user
      !pycmd enable_user         - Enable a disabled user
      !pycmd reset_app           - Reset the application
        """
        help_text += admin_help_text
    print(help_text)

def calculator():
    """Simple calculator application using tkinter."""
    def evaluate_expression(expression):
        try:
            result = eval(expression)
            result_var.set(result)
        except Exception as e:
            result_var.set("Error")

    calc_window = tk.Tk()
    calc_window.title("Simple Calculator")
    calc_window.geometry("300x200")  # Set fixed window size

    expression_var = tk.StringVar()
    result_var = tk.StringVar()

    tk.Entry(calc_window, textvariable=expression_var).pack()
    tk.Label(calc_window, textvariable=result_var).pack()
    tk.Button(calc_window, text="Calculate", command=lambda: evaluate_expression(expression_var.get())).pack()

    calc_window.mainloop()

def timer():
    """Countdown timer application using tkinter."""
    def start_timer(seconds):
        def countdown():
            nonlocal seconds
            if seconds >= 0:
                mins, secs = divmod(seconds, 60)
                timer_label.config(text=f"{mins:02d}:{secs:02d}")
                seconds -= 1
                timer_label.after(1000, countdown)
            else:
                messagebox.showinfo("Time's up!", "Time's up!")

        countdown()

    timer_window = tk.Tk()
    timer_window.title("Countdown Timer")

    seconds = simpledialog.askinteger("Input", "Enter time in seconds:", parent=timer_window)
    if seconds is not None:
        timer_label = tk.Label(timer_window, text="")
        timer_label.pack()
        tk.Button(timer_window, text="Start", command=lambda: start_timer(seconds)).pack()

    timer_window.mainloop()

def weather():
    """Simple weather application (mocked)."""
    print("Current Weather (mocked)")
    print("Location: New York")
    print("Temperature: 25°C")
    print("Condition: Sunny")

def run_dos_app(app_name):
    """Run a DOS application located in the script's directory."""
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(SCRIPT_DIR, app_name)
    if not os.path.exists(app_path):
        print(f"Application '{app_name}' not found in the script directory.")
        return
    
    try:
        result = subprocess.run(app_path, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with exit code {e.returncode}", file=sys.stderr)
        print(e.stderr, file=sys.stderr)

def execute_command(command, role, users, disabled_users):
    """Execute a system command and print the output."""
    print(f"Executing command: {command}")
    if command.startswith('!pycmd'):
        parts = command.split(maxsplit=2)
        pycmd_command = parts[1] if len(parts) > 1 else None
        if pycmd_command == 'list_users':
            list_users(users)
        elif pycmd_command == 'user_info' and len(parts) == 3:
            user_info(users, parts[2])
        elif pycmd_command == 'change_password':
            change_password(users)
        elif pycmd_command == 'delete_user' and role == 'admin':
            delete_user(users)
        elif pycmd_command == 'add_user' and role == 'admin':
            register_user(users)
        elif pycmd_command == 'disable_user' and role == 'admin':
            disable_user(users, disabled_users)
        elif pycmd_command == 'enable_user' and role == 'admin':
            enable_user(users, disabled_users)
        elif pycmd_command == 'reset_app' and role == 'admin':
            reset_app()
        elif pycmd_command == 'calc':
            calculator()
        elif pycmd_command == 'timer':
            timer()
        elif pycmd_command == 'weather':
            weather()
        elif pycmd_command == 'run' and len(parts) == 3:
            run_dos_app(parts[2])
        elif pycmd_command in ['delete_user', 'add_user', 'disable_user', 'enable_user', 'reset_app']:
            print("This command requires admin privileges.")
        else:
            print(f"Unknown !pycmd command: {pycmd_command}")
    else:
        try:
            if command.lower() in ['cmd', 'powershell']:
                print(f"Running '{command}' is not supported within PyCMD. Please run it in a separate terminal.")
                return

            if role == 'basic' and any(cmd in command.lower() for cmd in RESTRICTED_COMMANDS):
                print(f"Command '{command}' requires admin privileges and cannot be run by a basic user.")
                return

            result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}", file=sys.stderr)
            print(e.stderr, file=sys.stderr)

def main():
    print("Starting PyCMD...")
    users = load_users()
    disabled_users = load_disabled_users()
    if not users:
        print("No users found. Please register a new user.")
        register_user(users)

    while True:
        authenticated = False
        while not authenticated:
            choice = input("Do you want to (l)ogin, (r)egister, (d)elete user, or (e)xit? ").strip().lower()
            if choice == 'l':
                username, role = authenticate_user(users, disabled_users)
                authenticated = username is not None
            elif choice == 'r':
                register_user(users)
            elif choice == 'd':
                if not users:
                    print("No users available to delete.")
                    continue
                print("An admin is needed for this command!")
                admin_username, admin_role = authenticate_user(users, disabled_users)
                if admin_role == 'admin':
                    delete_user(users)
                else:
                    print("Only admin users can delete accounts.")
            elif choice == 'e':
                print("Exiting PyCMD. Goodbye!")
                return
            else:
                print("Invalid choice. Please enter 'l' for login, 'r' for register, 'd' for delete user, or 'e' for exit.")

        print("Welcome to PyCMD! Type 'help' for a list of available commands, 'logout' to log out, or 'exit' to quit.")
        while authenticated:
            try:
                command = input("PyCMD> ").strip()
                if command.lower() == 'exit':
                    print("Exiting PyCMD. Goodbye!")
                    return
                elif command.lower() == 'help':
                    show_help(role)
                elif command.lower() == 'logout':
                    authenticated = False
                    print("Logged out. Returning to login prompt.")
                elif command:
                    execute_command(command, role, users, disabled_users)
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\nKeyboardInterrupt (press 'exit' to quit)")

if __name__ == "__main__":
    main()
