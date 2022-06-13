import hashlib
import secrets

def hash_Func(password):
    #Define possible characters for salt, and setup chars array
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()"

    #pick 16 characters for salt and append them to end of password
    for i in range(16):
        password += str(secrets.choice(alphabet))
        print(password)

    #try hashing the password. We overwrite the original password variable to avoid storing it.
    try:
        password_UTF = password.encode('utf-8')
        sha512_Hash = hashlib.sha512()
        sha512_Hash.update(password_UTF)
        password = sha512_Hash.hexdigest()

    #if there's a problem hashing, throw an error.
    except:
        #Erase password variable for security
        password = None
        print("Error. Please Try again. You probably used illegal characters, or it was too long. "
              "Try using only 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*() "
              "with a max length of 32.")

    return password

if __name__ == '__main__':
    print("Your password hash is: ",
        hash_Func(
            input("Please type a password >33 characters long using A-Z, a-z, 0-9, and !-) ")))
