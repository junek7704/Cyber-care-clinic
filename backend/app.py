from flask import Flask, request, jsonify,send_from_directory, session, redirect, url_for, render_template
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import os

app = Flask(__name__, static_folder="../frontend", static_url_path="/")
app.secret_key = "supersecretkey"  # you can change this to something stronger
CORS(app, supports_credentials=True)


# ----------------------------
# MongoDB Setup
# ----------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["cybercare_clinic"]
incidents_collection = db["incidents"]
resources_collection = db["resources"]
guides_collection = db["incident_guides"]
users_collection = db["users"]
activity_collection = db["activity_logs"]

# ----------------------------
# USER ROUTES (read-only for guides)
# ----------------------------

from datetime import datetime

def log_activity(action, user, details=""):
    db.activity_logs.insert_one({
        "timestamp": datetime.utcnow(),
        "action": action,
        "user": user,
        "details": details
    })


# Register new user
@app.route("/register", methods=["POST"])
def register_user():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not all([name, email, password]):
        return jsonify({"error": "All fields are required"}), 400

    if db.users.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    db.users.insert_one({
        "name": name,
        "email": email,
        "password": hashed_pw
    })

    return jsonify({"message": "User registered successfully"}), 201

@app.route("/")
def home():
    frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))
    file_path = os.path.join(frontend_path, "user-login.html")

    if os.path.exists(file_path):
        return send_from_directory(frontend_path, "user-login.html")
    else:
        return f"❌ Login page not found. Expected at: {file_path}", 404

## LOGIN (user + admin combined)
@app.route("/login", methods=["POST"])
def login_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    role = "user"

    # If not found in users, check admins collection
    if not user:
        user = db.admins.find_one({"email": email})
        role = "admin" if user else None

    if not user:
        print("❌ User/admin not found:", email)
        return jsonify({"error": "Invalid email or password"}), 400

    stored_password = user["password"]

    # Convert to bytes if needed
    if isinstance(stored_password, bytes):
        hashed_pw = stored_password
    else:
        hashed_pw = stored_password.encode("utf-8")

    try:
        if not bcrypt.checkpw(password.encode("utf-8"), hashed_pw):
            print("❌ Password mismatch")
            return jsonify({"error": "Invalid email or password"}), 400
    except Exception as e:
        print("⚠️ bcrypt error:", e)
        return jsonify({"error": "Server error during password check"}), 500

    # Store session info
    session["user_id"] = str(user["_id"])
    session["user_name"] = user.get("name")
    session["role"] = role

    print(f"✅ Login successful for {role}:", email)

    # ✅ Log the login activity
    try:
        log_activity(
            action="Login",
            user=user.get("name", email),
            details=f"{role.capitalize()} logged in successfully."
        )
    except Exception as e:
        print(f"⚠️ Could not log activity: {e}")

    # Redirect URLs
    redirect_url = "/admin/admin-dashboard.html" if role == "admin" else "/dashboard/index.html"

    return jsonify({
        "message": "Login successful",
        "name": user["name"],
        "role": role,
        "redirect": redirect_url
    }), 200



@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login_page"))

    dashboard_path = os.path.abspath(os.path.join(os.getcwd(), "../frontend/dashboard"))
    file_path = os.path.join(dashboard_path, "index.html")

    if os.path.exists(file_path):
        return send_from_directory(dashboard_path, "index.html")
    else:
        return f"❌ Dashboard file not found at: {file_path}", 404


@app.route("/incident-report", methods=["POST"])
def report_incident():
    try:
        data = request.json
        incident = {
            "name": data.get("name"),
            "email": data.get("email"),
            "type_of_incident": data.get("type_of_incident"),
            "incident_description": data.get("incident-description"),
            "date_of_incident": data.get("date_of_incident")
        }

        incidents_collection.insert_one(incident)

        # ✅ Log the activity
        try:
            log_activity(
                action="Incident Reported",
                user=data.get("name", "Anonymous"),
                details=f"Reported a {data.get('type_of_incident', 'General')} incident."
            )
        except Exception as log_error:
            print(f"⚠️ Could not log activity: {log_error}")

        return jsonify({"message": "Incident reported successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

     

@app.route("/incidents", methods=["GET"])
def get_incidents():
    try:
        incidents = list(incidents_collection.find({}, {"_id": 0}))
        return jsonify(incidents), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Fetch all incident guides (read-only for users)
@app.route("/incident-guides", methods=["GET"])
def get_incident_guides():
    try:
        guides = []
        for guide in guides_collection.find():
            guide["_id"] = str(guide["_id"])  # convert ObjectId to string
            guides.append(guide)
        return jsonify(guides), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------------------------
# ADMIN ROUTES (add, edit, delete)
# ----------------------------

# Add new guide
@app.route("/admin/add-guide", methods=["POST"])
def admin_add_guide():
    try:
        data = request.json
        guide = {
            "incident_type": data.get("incident_type"),
            "steps": data.get("steps", [])
        }
        # Optional: log what’s being inserted
        print("Adding guide:", guide)
        guides_collection.insert_one(guide)
        return jsonify({"message": "Guide added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update guide
@app.route("/admin/guide/<guide_id>", methods=["PUT"])
def admin_update_guide(guide_id):
    try:
        data = request.json
        update_data = {
            "incident_type": data.get("incident_type"),
            "steps": data.get("steps", [])
        }
        result = guides_collection.update_one(
            {"_id": ObjectId(guide_id)},
            {"$set": update_data}
        )
        if result.matched_count:
            return jsonify({"message": "Guide updated successfully"}), 200
        else:
            return jsonify({"error": "Guide not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete guide
@app.route("/admin/guide/<guide_id>", methods=["DELETE"])
def admin_delete_guide(guide_id):
    try:
        result = guides_collection.delete_one({"_id": ObjectId(guide_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Guide deleted successfully"}), 200
        else:
            return jsonify({"error": "Guide not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ✅ Route to add a new support resource
@app.route('/add-resource', methods=['POST'])
def add_resource():
    try:
        data = request.get_json()

        # Extract fields
        title = data.get('title')
        description = data.get('description')
        link = data.get('link')
        category = data.get('category')
        icon = data.get('icon', '📘')

        # Basic validation
        if not title or not description or not category:
            return jsonify({"error": "Missing required fields"}), 400

        # Build the resource object
        new_resource = {
            "title": title,
            "description": description,
            "link": link,
            "category": category,
            "icon": icon
        }

        # ✅ Actually insert into MongoDB
        resources_collection.insert_one(new_resource)

        print("✅ New resource added to DB:", new_resource)

        return jsonify({"message": "Resource added successfully"}), 200

    except Exception as e:
        print("❌ Error in /add-resource:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/api/resources', methods=['GET'])
def get_resources():
    resources = list(resources_collection.find({}, {"_id": 0}))
    return jsonify(resources), 200

    # --- ADMIN LOGIN ROUTE ---
@app.route("/admin-login", methods=["POST"])
def admin_login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        # Find admin in database
        admin = db.admins.find_one({"username": username, "password": password})

        if admin:
            session["admin"] = str(admin["_id"])  # create session
            return jsonify({"message": "Login successful", "status": "success"}), 200
        else:
            return jsonify({"message": "Invalid username or password", "status": "fail"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- LOGOUT ROUTE ---
@app.route("/admin-logout", methods=["POST"])
def admin_logout():
    session.pop("admin", None)
    return jsonify({"message": "Logged out successfully"}), 200


# --- CHECK SESSION ROUTE ---
@app.route("/check-admin", methods=["GET"])
def check_admin():
    if "admin" in session:
        return jsonify({"logged_in": True}), 200
    else:
        return jsonify({"logged_in": False}), 200
    
@app.route("/admin-dashboard")
def admin_dashboard():
    return send_from_directory(os.path.join(app.static_folder, "admin"), "admin-dashboard.html")


@app.route("/dashboard")
def user_dashboard():
    return send_from_directory(os.path.join(app.static_folder, "dashboard"), "index.html")  
@app.route('/<path:filename>')
def serve_static_files(filename):
    frontend_path = os.path.join(os.getcwd(), "frontend")
    file_path = os.path.join(frontend_path, filename)

    if os.path.exists(file_path):
        return send_from_directory(frontend_path, filename)
    else:
        return jsonify({"error": "File not found"}), 404

@app.route("/admin/profile-data")
def get_admin_profile():
    if "role" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized access"}), 403

    admin = db.admins.find_one({"_id": ObjectId(session["user_id"])})
    if not admin:
        return jsonify({"error": "Admin not found"}), 404

    return jsonify({
        "name": admin.get("name"),
        "email": admin.get("email"),
        "username": admin.get("username")
    })

from datetime import datetime

@app.route("/admin/update-profile", methods=["POST"])
def update_admin_profile():
    if "role" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    updates = {}
    if data.get("name"):
        updates["name"] = data["name"]
    if data.get("phone"):
        updates["phone"] = data["phone"]

    db.admins.update_one({"_id": ObjectId(session["user_id"])}, {"$set": updates})


    log_activity("Profile Update", session["username"], f"Updated details: {list(updates.keys())}")
    return jsonify({"message": "Profile updated successfully"})


@app.route("/admin/change-password", methods=["POST"])
def change_admin_password():
    if "role" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    admin = db.admins.find_one({"_id": ObjectId(session["user_id"])})
    if not admin:
        return jsonify({"error": "Admin not found"}), 404

    if not bcrypt.checkpw(old_password.encode("utf-8"), admin["password"]):
        return jsonify({"error": "Old password is incorrect"}), 400

    hashed_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    db.admins.update_one({"_id": admin["_id"]}, {"$set": {"password": hashed_pw}})

    log_activity("Password Change", session["username"], "Admin changed password")
    return jsonify({"message": "Password changed successfully"})

@app.route("/admin/toggle-2fa", methods=["POST"])
def toggle_2fa():
    if "role" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    enabled = data.get("enabled", False)
    db.admins.update_one({"_id": ObjectId(session["user_id"])}, {"$set": {"twofa_enabled": enabled}})
    log_activity("2FA Toggle", session["username"], f"2FA {'enabled' if enabled else 'disabled'}")
    return jsonify({"message": f"2FA {'enabled' if enabled else 'disabled'}"})

@app.route("/admin/activity-logs")
def admin_activity_logs():
    if "role" not in session or session["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    logs = list(db.activity_logs.find().sort("timestamp", -1))
    for log in logs:
        log["_id"] = str(log["_id"])
    return jsonify(logs)

# ------------------------------------------
# 🔔 CREATE A NEW NOTIFICATION
# ------------------------------------------
@app.route("/notify", methods=["POST"])
def create_notification():
    data = request.get_json()
    if not data or "message" not in data:
        return jsonify({"error": "Message field is required"}), 400

    notification = {
        "message": data["message"],
        "timestamp": datetime.utcnow(),
        "is_read": False
    }

    db.notifications.insert_one(notification)
    return jsonify({"message": "Notification created successfully!"}), 201


# ------------------------------------------
# 📬 GET ALL NOTIFICATIONS (Admin Side)
# ------------------------------------------
@app.route("/notifications", methods=["GET"])
def get_notifications():
    notifications = list(db.notifications.find().sort("timestamp", -1))
    formatted = []
    for note in notifications:
        formatted.append({
            "_id": str(note["_id"]),
            "message": note.get("message", ""),
            "timestamp": note["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "is_read": note.get("is_read", False)
        })
    return jsonify(formatted)


# ------------------------------------------
# ✅ MARK NOTIFICATION AS READ
# ------------------------------------------
@app.route("/notifications/<notification_id>/read", methods=["PUT"])
def mark_notification_as_read(notification_id):
    try:
        result = db.notifications.update_one(
            {"_id": ObjectId(notification_id)},
            {"$set": {"is_read": True}}
        )
        if result.matched_count == 0:
            return jsonify({"error": "Notification not found"}), 404
        return jsonify({"message": "Notification marked as read"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True, use_reloader=False, port=5000)
