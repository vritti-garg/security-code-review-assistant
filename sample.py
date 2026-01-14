import os

# 1. Auth Risk (FunctionDef)
def login_user(username, password):
    # 2. Input Risk (Call)
    cmd = input("Enter command: ")
    
    # 3. System Call Risk (Call)
    os.system(cmd)

# 4. File Risk (Call)
f = open("data.txt", "r")