import re
import requests

# Function to evaluate password strength
def analyze_password_strength(password):
    score = 0
    feedback = []
    
    # Check password length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short. Use at least 12 characters.")
    
    # Check for mix of uppercase, lowercase, numbers, and special characters
    if re.search("[a-z]", password):
        score += 1
    else:
        feedback.append("Password should contain at least one lowercase letter.")
    
    if re.search("[A-Z]", password):
        score += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")
    
    if re.search("[0-9]", password):
        score += 1
    else:
        feedback.append("Password should contain at least one digit.")
    
    if re.search("[@#$%^&*!]", password):
        score += 1
    else:
        feedback.append("Password should contain at least one special character (@, #, $, %, etc.).")
    
    # Check for common patterns (sequences like '1234', 'abcd')
    if re.search(r"(.)\1\1", password):
        feedback.append("Password contains repeated characters or sequences.")
    
    if re.search(r"(123|abc|qwerty|password|letmein)", password, re.IGNORECASE):
        feedback.append("Password contains common words or patterns (e.g., '123', 'password').")
    
    # Check if the password has been involved in data breaches (via an API)
    if is_password_breached(password):
        feedback.append("This password has been found in known breaches. Avoid using breached passwords.")
    
    # Determine password strength level
    if score >= 6:
        return "Strong Password", feedback
    elif score >= 3:
        return "Moderate Password", feedback
    else:
        return "Weak Password", feedback

# Function to check if the password has been breached using "Have I Been Pwned" API
def is_password_breached(password):
    hashed_password = sha1_hash(password)
    first5_chars = hashed_password[:5]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{first5_chars}")
    
    if response.status_code == 200:
        breaches = response.text.splitlines()
        for line in breaches:
            hash_suffix, count = line.split(":")
            if hashed_password[5:].upper() == hash_suffix:
                return True
    return False

# Function to compute SHA-1 hash of the password (as required by the API)
import hashlib
def sha1_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()

# Example usage
if __name__ == "__main__":
    password = input("Enter a password to analyze: ")
    strength, feedback = analyze_password_strength(password)
    
    print(f"Password Strength: {strength}")
    if feedback:
        print("Suggestions for improvement:")
        for suggestion in feedback:
            print(f"- {suggestion}")
