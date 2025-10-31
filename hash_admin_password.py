from pymongo import MongoClient
import bcrypt

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cybercare_clinic"]

# Admin credentials to update
admin_email = "junek@gmail.com"   # ← put your admin email here
new_password = "admin123"         # ← put your desired password here

# Hash the password
hashed_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())

# Update the admin password in the database
result = db.admins.update_one(
    {"email": admin_email},
    {"$set": {"password": hashed_pw}}
)

print("✅ Password updated for admin:", admin_email)
print("Matched:", result.matched_count, "Modified:", result.modified_count)
