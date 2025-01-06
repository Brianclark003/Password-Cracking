# Import required libraries from pwntools and sys for argument parsing
from pwn import *
import sys

# Check if the correct number of arguments is passed (script name + hash to search for)
if len(sys.argv) != 2:
    print("Invalid arguments!")
    print("Usage: {} <sha256sum>".format(sys.argv[0]))  # Display correct usage format
    exit()  # Exit the program if the wrong number of arguments is passed

# Extract the wanted hash from the command-line argument
wanted_hash = sys.argv[1]

# Open the 'rockyou.txt' password file for reading (used as a wordlist for potential passwords)
password_file = open("rockyou.txt")

# Initialize a counter to track the number of password attempts
attempts = 0    

# Start logging the process of cracking the hash
with log.process("Attempting to back: {}!\n".format(wanted_hash)) as p:
    # Open the password file and read each password, using 'latin-1' encoding to support non-ASCII characters
    with open(password_file, "r", encoding='latin-1') as password_list:
        # Iterate through each password in the file
        for password in password_list:
            password = password.strip("\n").encode('latin-1')  # Remove newlines and encode password in latin-1
            
            # Compute the SHA-256 hash of the current password
            password_hash = sha256sum(password)
            
            # Log the current attempt, displaying the password and its hash
            p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
            
            # Check if the computed hash matches the wanted hash
            if password_hash == wanted_hash:
                # If a match is found, log success and exit the loop
                p.success("Password hash found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()  # Exit once the correct password is found
            
            attempts += 1  # Increment the attempt counter
            
            # If password hash does not match, log failure for this attempt
            p.failure("Password hash not found!")
