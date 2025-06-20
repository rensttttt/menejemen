import bcrypt

password = b"Admin1234"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed.decode())
