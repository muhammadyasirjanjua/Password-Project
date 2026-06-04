import secrets
import string

def generate_password(strength, length):
    length = int(length)
    if strength == "enterprise":
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    elif strength == "very_strong":
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
    else: # strong
        chars = string.ascii_letters + string.digits
        
    # Ensure at least one of each required type
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        if strength == "strong":
            if any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and any(c.isdigit() for c in pwd):
                return pwd
        else:
            if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and 
                any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)):
                return pwd
