import os

def backup_data():
    # This is safe (Hardcoded) - Triggers R001
    os.system("tar -czf backup.tar.gz /data")

def malicious_admin_tool():
    # This triggers R003 (Input)
    cmd = input("Enter command to run: ")
    
    os.system(cmd)

def safe_function():
    print("Just printing stuff")