from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import pytesseract
from PIL import Image
from flask_mail import Mail, Message
import random
import string
import cv2
import re
import os
from werkzeug.utils import secure_filename
from flask_cors import CORS
import numpy as np
import math

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

app = Flask(__name__)
CORS(app)


#   =====   CONFIG  =====
app.config["JWT_SECRET_KEY"] = "catatkunci"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.secret_key = "uniqekey"
client = MongoClient("mongodb://localhost:27017/")
db = client["capstone_app_db"]
jwt = JWTManager(app)

#   =====   CONFIG EMAIL    =====
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'eghinansyah554@gmail.com' 
app.config['MAIL_PASSWORD'] = 'sget djzi easq efec'
mail = Mail(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

#   =====   PAGE    =====
@app.route("/")
def landing_page():
    return render_template("index.html")

#   =====   UTILS   =====
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def user_schema(user):
    return {"id": str(user["_id"]), "username": user["username"], "role": user["role"]}

def transaction_schema(txn):
    return {
        "id": str(txn["_id"]),
        "user_id": str(txn["user_id"]),
        "type": txn["type"],
        "name": txn["name"],
        "items": txn["items"],  # ganti dari 'item' ke 'items'
        "total_price": txn["total_price"],  # ganti dari 'price'
        "account": txn["account"],
        "note": txn.get("note", ""),
        "date": txn["date"].isoformat()  # convert datetime to string for JSON
    }


def account_schema(acc):
    return {"id": str(acc["_id"]), "user_id": str(acc["user_id"]), "name": acc["name"], "balance": acc["balance"]}

def extract_text_from_image(path):
    img = Image.open(path)
    return pytesseract.image_to_string(img)

def log_activity(user_id, action, details=None):
    log = {
        "user_id": ObjectId(user_id),
        "action": action,  # "login", "logout", "register", "reset_password"
        "timestamp": datetime.now(),
        "details": details or {}
    }
    db.audit_logs.insert_one(log)


#   =====   UTILS: Admin Check  =====
def is_admin(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    return user and user.get("role") == "admin"

@app.route("/audit-log", methods=["GET"])
@jwt_required()
def get_audit_log():
    user_id = get_jwt_identity()
    logs = db.audit_logs.find({
        "user_id": ObjectId(user_id),
        "action": "login"
    }).sort("timestamp", -1)

    return render_template("audit_log.html", logs=logs)

@app.route("/api/audit-log")
@jwt_required()
def api_audit_log():
    user_id = get_jwt_identity()
    page = int(request.args.get("page", 1))
    limit = 10
    skip = (page - 1) * limit

    logs_cursor = db.audit_logs.find({"user_id": ObjectId(user_id)}).sort("timestamp", -1).skip(skip).limit(limit)
    total_logs = db.audit_logs.count_documents({"user_id": ObjectId(user_id)})

    logs = []
    for log in logs_cursor:
        logs.append({
            "timestamp": log["timestamp"].isoformat(),
            "action": log["action"],
            "details": log.get("details", {}),
            "username": db.users.find_one({"_id": log["user_id"]}).get("username", "-")
        })

    return jsonify({
        "logs": logs,
        "has_prev": page > 1,
        "has_next": (page * limit) < total_logs
    })



@app.route("/admin/users", methods=["GET"])
@jwt_required()
def admin_get_users():
    user_id = get_jwt_identity()
    if not is_admin(user_id):
        return jsonify({"msg": "Akses ditolak. Bukan admin"}), 403

    users = db.users.find()
    result = []
    for u in users:
        result.append({
            "id": str(u["_id"]),
            "username": u["username"],
            "email": u["email"],
            "role": u.get("role", "user")
        })
    return jsonify(result)

@app.route("/admin/transactions", methods=["GET"])
@jwt_required()
def admin_get_transactions():
    user_id = get_jwt_identity()
    if not is_admin(user_id):
        return jsonify({"msg": "Akses ditolak. Bukan admin"}), 403

    txns = db.transactions.find()
    return jsonify([transaction_schema(t) for t in txns])

@app.route("/admin/user/<user_id>", methods=["DELETE"])
@jwt_required()
def admin_delete_user(user_id):
    admin_id = get_jwt_identity()
    if not is_admin(admin_id):
        return jsonify({"msg": "Akses ditolak. Bukan admin"}), 403

    result = db.users.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        return jsonify({"msg": "User tidak ditemukan"}), 404

    # Hapus juga akun & transaksi milik user tersebut
    db.accounts.delete_many({"user_id": ObjectId(user_id)})
    db.transactions.delete_many({"user_id": ObjectId(user_id)})

    return jsonify({"msg": "User dan data terkait telah dihapus"})

@app.route("/admin/transaction/<txn_id>", methods=["DELETE"])
@jwt_required()
def admin_delete_transaction(txn_id):
    admin_id = get_jwt_identity()
    if not is_admin(admin_id):
        return jsonify({"msg": "Akses ditolak. Bukan admin"}), 403

    result = db.transactions.delete_one({"_id": ObjectId(txn_id)})
    if result.deleted_count == 0:
        return jsonify({"msg": "Transaksi tidak ditemukan"}), 404

    return jsonify({"msg": "Transaksi berhasil dihapus"})

#   =====   ADMIN MANAGE    =====
@app.route("/admin/manage-users")
def admin_manage_users():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    return render_template("admin_users.html")

@app.route("/admin/manage-transactions")
def admin_manage_transactions():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    return render_template("admin_transactions.html")


#   =====   ADMIN LOGIN PAGE    =====
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Debugging: Print input values
        print(f"Login attempt - Username: {username}, Password: {password}")

        user = db.users.find_one({"username": username})
        
        # Debugging: Print user data
        if user:
            print(f"User found: {user}, Role: {user.get('role')}")
        else:
            print("User not found")

        # Enhanced validation
        if not user or user.get("role", "").lower() != "admin":
            print("Role validation failed")
            return render_template("admin_login.html", 
                                error="Akses ditolak. Hanya admin yang boleh login"), 403

        if not check_password_hash(user["password"], password):
            print("Password mismatch")
            return render_template("admin_login.html", 
                                error="Username atau password salah"), 401

        # Secure session setup
        session.permanent = True
        session["admin_id"] = str(user["_id"])
        session["admin_username"] = user["username"]
        session["admin_logged_in"] = True

        # Debugging: Print session after set
        print(f"Session after login: {dict(session)}")

        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")

#   =====   ADMIN DASHBOARD   =====
@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    
    # Get recent login/logout activities for accounting section
    accounting_activities = list(db.audit_logs.find({
        "action": {"$in": ["login", "logout"]}
    }).sort("timestamp", -1).limit(5))
    
    # Process activities for accounting display
    processed_accounting = []
    for act in accounting_activities:
        user = db.users.find_one({"_id": act["user_id"]})
        processed_accounting.append({
            "platform": "Windows 10",  # Simplified - should parse user agent
            "browser": "Chrome",       # Simplified - should parse user agent
            "ip_address": act.get("details", {}).get("ip", "Unknown"),
            "login_time": act["timestamp"] if act["action"] == "login" else None,
            "last_activity": act["timestamp"],
            "logout_time": act["timestamp"] if act["action"] == "logout" else None,
            "status": "Active" if act["action"] == "login" else "Inactive",
            "username": user["username"] if user else "Unknown"
        })
    
    return render_template("admin_dashboard.html", 
                         username=session["admin_username"],
                         accounting_activities=processed_accounting,
                         now=datetime.now())

#   =====   ADMIN LOGOUT    =====
@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


@app.route('/admin/recent-auth-logs')
def recent_auth_logs():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    skip = (page - 1) * limit

    # Ambil log dari MongoDB collection 'audit_logs'
    logs_cursor = db.audit_logs.find(
        {"action": {"$in": ["login", "logout", "register", "reset_password"]}}
    ).sort("timestamp", -1).skip(skip).limit(limit)

    activities = []
    for log in logs_cursor:
        # Ambil username dari koleksi users
        user_doc = db.users.find_one({"_id": log["user_id"]})
        username = user_doc["username"] if user_doc else "Unknown"

        activities.append({
            "timestamp": log["timestamp"].isoformat(),
            "username": username,
            "action": log["action"],
            "details": log.get("details", {}),
            "success": log.get("details", {}).get("success", True)  # Default ke True jika tidak dicatat
        })

    total_logs = db.audit_logs.count_documents({"action": {"$in": ["login", "logout", "register", "reset_password"]}})

    return jsonify({
        "activities": activities,
        "total": total_logs,
        "page": page
    })


#   =====   AUTH    =====
from flask import request, jsonify
from werkzeug.security import generate_password_hash
from datetime import datetime
import random
from flask_mail import Message

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if db.users.find_one({"username": username}):
        return jsonify({"msg": "Username sudah terdaftar"}), 400

    if db.users.find_one({"email": email}):
        return jsonify({"msg": "Email sudah terdaftar"}), 400

    otp = str(random.randint(100000, 999999))

    user = {
        "username": username,
        "email": email,
        "password": generate_password_hash(password),
        "role": "user",
        "verified": False,
        "otp": otp,
        "otp_created": datetime.now()
    }

    result = db.users.insert_one(user)
    log_activity(str(result.inserted_id), "register", {"email": email})

    try:
        msg = Message(
            subject="Kode Verifikasi Akun",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email],
            body=f"Halo {username},\n\nKode OTP verifikasi kamu adalah: {otp}\n\nMasukkan kode ini di aplikasi untuk mengaktifkan akun kamu."
        )
        mail.send(msg)
    except Exception as e:
        return jsonify({"msg": f"Registrasi gagal saat kirim email: {str(e)}"}), 500

    return jsonify({"msg": "Registrasi berhasil. Silakan cek email untuk OTP verifikasi."}), 201


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"msg": "User tidak ditemukan"}), 404

    if user.get("verified"):
        return jsonify({"msg": "Akun sudah diverifikasi"}), 400

    # Tambahkan pengecekan OTP kadaluarsa di sini
    if "otp_created" not in user or (datetime.now() - user["otp_created"]) > timedelta(minutes=10):
        return jsonify({"msg": "Kode OTP sudah kedaluwarsa"}), 400

    if user.get("otp") != otp:
        return jsonify({"msg": "Kode OTP salah"}), 400

    db.users.update_one({"_id": user["_id"]}, {
        "$set": {"verified": True},
        "$unset": {"otp": "", "otp_created": ""}
    })

    return jsonify({"msg": "Verifikasi berhasil. Silakan login."}), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = db.users.find_one({"username": username})

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"msg": "Username atau password salah"}), 401

    if not user.get("verified", False):
        return jsonify({"msg": "Akun belum diverifikasi. Silakan masukkan OTP dari email."}), 403
    log_activity(str(user["_id"]), "login", {"ip": request.remote_addr})

    token = create_access_token(identity=str(user["_id"]))
    return jsonify({
        "access_token": token,
        "username": user["username"],
        "email": user["email"]
    })

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"msg": "Email tidak ditemukan"}), 404

    otp = str(random.randint(100000, 999999))
    db.users.update_one({"_id": user["_id"]}, {
        "$set": {
            "reset_otp": otp,
            "reset_otp_created": datetime.now()
        }
    })

    try:
        msg = Message(
            subject="Reset Password OTP",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email],
            body=f"Halo {user['username']},\n\nKode OTP untuk reset password adalah: {otp}\nMasukkan kode ini untuk mengatur ulang password kamu."
        )
        mail.send(msg)
    except Exception as e:
        return jsonify({"msg": f"Gagal mengirim OTP: {str(e)}"}), 500

    return jsonify({"msg": "OTP untuk reset password telah dikirim ke email."}), 200


@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("new_password")

    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"msg": "User tidak ditemukan"}), 404

    if "reset_otp_created" not in user or (datetime.now() - user["reset_otp_created"]) > timedelta(minutes=10):
        return jsonify({"msg": "Kode OTP sudah kedaluwarsa"}), 400

    if user.get("reset_otp") != otp:
        return jsonify({"msg": "Kode OTP salah"}), 400

    db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"password": generate_password_hash(new_password)},
            "$unset": {"reset_otp": "", "reset_otp_created": ""}
        }
    )

    log_activity(str(user["_id"]), "reset_password", {"email": email, "ip": request.remote_addr})
    return jsonify({"msg": "Password berhasil direset. Silakan login dengan password baru."}), 200



@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    log_activity(user_id, "logout", {"ip": request.remote_addr})
    return jsonify({"msg": "Logout berhasil. Silakan hapus token di client."}), 200




#   =====   ACCOUNT =====
@app.route("/account", methods=["POST"])
@jwt_required()
def add_account():
    user_id = get_jwt_identity()
    data = request.json
    acc = {
        "user_id": ObjectId(user_id),
        "name": data["name"],
        "balance": data.get("balance", 0)
    }
    db.accounts.insert_one(acc)
    return jsonify({"msg": "Rekening ditambahkan"}), 201

@app.route("/account", methods=["GET"])
@jwt_required()
def get_accounts():
    user_id = get_jwt_identity()
    accs = db.accounts.find({"user_id": ObjectId(user_id)})
    return jsonify([account_schema(a) for a in accs])

# UPDATE rekening
@app.route("/account/<acc_id>", methods=["PUT"])
@jwt_required()
def update_account(acc_id):
    user_id = get_jwt_identity()
    data = request.json

    if not data.get("name"):
        return jsonify({"msg": "Nama rekening wajib diisi"}), 400

    acc = db.accounts.find_one({"_id": ObjectId(acc_id), "user_id": ObjectId(user_id)})
    if not acc:
        return jsonify({"msg": "Rekening tidak ditemukan"}), 404

    db.accounts.update_one({"_id": ObjectId(acc_id)}, {"$set": {"name": data["name"], 'balance' : data['balance']}})
    return jsonify({"msg": "Rekening berhasil diperbarui"})


# DELETE rekening
@app.route("/account/<acc_id>", methods=["DELETE"])
@jwt_required()
def delete_account(acc_id):
    user_id = get_jwt_identity()
    acc = db.accounts.find_one({"_id": ObjectId(acc_id), "user_id": ObjectId(user_id)})
    if not acc:
        return jsonify({"msg": "Rekening tidak ditemukan"}), 404

    # Cek apakah masih ada transaksi yang pakai rekening ini
    if db.transactions.find_one({"user_id": ObjectId(user_id), "account": acc["name"]}):
        return jsonify({"msg": "Tidak bisa hapus. Rekening masih digunakan dalam transaksi"}), 400

    db.accounts.delete_one({"_id": ObjectId(acc_id)})
    return jsonify({"msg": "Rekening berhasil dihapus"})


#   ===== TRANSACTIONS  =====
@app.route("/transaction", methods=["POST"]) 
@jwt_required()
def add_transaction():
    user_id = get_jwt_identity()
    data = request.json

    items = data.get("items", [])
    if not items or not isinstance(items, list):
        return jsonify({'msg' : 'Item harus berupa list'}), 400

    total_price = sum(item['price'] for item in items)

    txn = {
        "user_id": ObjectId(user_id),
        "type": data["type"],  # income / expense
        "name": data["name"],
        "items": items,
        "total_price": total_price,
        "account": data["account"],
        "note": data.get("note", ""),
        "date": datetime.now()
    }
    db.transactions.insert_one(txn)

    # Update account balance    
    acc = db.accounts.find_one({"user_id": ObjectId(user_id), "name": data["account"]})
    if acc:
        if data['type'] == "income":
            new_balance = acc['balance'] + total_price
        if data['type'] == "expense":
            new_balance = acc['balance'] - total_price

        db.accounts.update_one({"_id": acc["_id"]}, {"$set": {"balance": new_balance}})
    return jsonify({"msg": "Transaksi ditambahkan"}), 201

@app.route("/transaction", methods=["GET"])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    txns = db.transactions.find({"user_id": ObjectId(user_id)})
    return jsonify([transaction_schema(t) for t in txns])

# UPDATE transaksi
@app.route("/transaction/<txn_id>", methods=["PUT"])
@jwt_required()
def update_transaction(txn_id):
    user_id = get_jwt_identity()
    data = request.json

    # Validasi input
    if not all(key in data for key in ("type", "name", "item", "price", "account")):
        return jsonify({"msg": "Field wajib: type, name, item, price, account"}), 400

    try:
        data["price"] = float(data["price"])
    except:
        return jsonify({"msg": "Harga harus berupa angka"}), 400

    txn = db.transactions.find_one({"_id": ObjectId(txn_id), "user_id": ObjectId(user_id)})
    if not txn:
        return jsonify({"msg": "Transaksi tidak ditemukan"}), 404

    # Rollback saldo lama
    acc = db.accounts.find_one({"user_id": ObjectId(user_id), "name": txn["account"]})
    if acc:
        rollback = txn["price"] if txn["type"] == "income" else -txn["price"]
        db.accounts.update_one({"_id": acc["_id"]}, {"$inc": {"balance": -rollback}})

    # Update transaksi
    db.transactions.update_one(
        {"_id": ObjectId(txn_id)},
        {"$set": {
            "type": data["type"],
            "name": data["name"],
            "item": data["item"],
            "price": data["price"],
            "account": data["account"],
            "note": data.get("note", ""),
            "date": datetime.now()
        }}
    )

    # Update saldo baru
    new_acc = db.accounts.find_one({"user_id": ObjectId(user_id), "name": data["account"]})
    if new_acc:
        adj = data["price"] if data["type"] == "income" else -data["price"]
        db.accounts.update_one({"_id": new_acc["_id"]}, {"$inc": {"balance": adj}})

    return jsonify({"msg": "Transaksi berhasil diperbarui"})


# DELETE transaksi
@app.route("/transaction/<txn_id>", methods=["DELETE"])
@jwt_required()
def delete_transaction(txn_id):
    user_id = get_jwt_identity()
    txn = db.transactions.find_one({"_id": ObjectId(txn_id), "user_id": ObjectId(user_id)})
    if not txn:
        return jsonify({"msg": "Transaksi tidak ditemukan"}), 404

    # Update saldo rollback
    acc = db.accounts.find_one({"user_id": ObjectId(user_id), "name": txn["account"]})
    if acc:
        adj = txn["total_price"] if txn["type"] == "income" else -txn["total_price"]
        db.accounts.update_one({"_id": acc["_id"]}, {"$inc": {"balance": -adj}})

    db.transactions.delete_one({"_id": ObjectId(txn_id)})
    return jsonify({"msg": "Transaksi berhasil dihapus"})


#   =====   SUMMARY =====
@app.route("/summary", methods=["GET"])
@jwt_required()
def get_summary():
    user_id = get_jwt_identity()
    txns = list(db.transactions.find({"user_id": ObjectId(user_id)}))
    income = sum(t["price"] for t in txns if t["type"] == "income")
    expense = sum(t["price"] for t in txns if t["type"] == "expense")
    return jsonify({"total_income": income, "total_expense": expense})

#   =====   OCR =====

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    user_id = get_jwt_identity()

    if 'image' not in request.files:
        return jsonify({'error': 'No image part'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        npimg = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        # Preprocessing
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blur = cv2.GaussianBlur(gray, (5, 5), 0)
        thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]

        # OCR
        custom_config = r'--oem 3 --psm 6'
        text = pytesseract.image_to_string(thresh, config=custom_config)

        # Ekstraksi
        lines = text.splitlines()
        extracted_items = []
        pattern = re.compile(r'^(.*?)\s*[-:\s]\s*Rp?\s*([\d.,]+)$', re.IGNORECASE)

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = pattern.search(line)
            if match:
                nama_item = match.group(1).strip()
                harga_str = match.group(2).replace('.', '').replace(',', '.')

                if any(keyword in nama_item.lower() for keyword in ['total', 'metode', 'jumlah', 'bayar']):
                    continue

                try:
                    harga = float(harga_str)
                    extracted_items.append({
                        "nama": nama_item,
                        "harga": harga
                    })
                except ValueError:
                    continue

        # Hitung total harga
        total_price = sum(item['harga'] for item in extracted_items)

        # Simpan transaksi ke DB
        account_name = "Dompet"  # default akun
        data_transaksi = {
            "user_id": ObjectId(user_id),
            "type": "expense",
            "name": "Belanja dari Struk",
            "items": extracted_items,
            "total_price": total_price,
            "account": account_name,
            "note": "Transaksi otomatis dari OCR",
            "date": datetime.now()
        }

        db.transactions.insert_one(data_transaksi)

        # Update saldo rekening
        account = db.accounts.find_one({"user_id": ObjectId(user_id), "name": account_name})
        if account:
            db.accounts.update_one(
                {"_id": account["_id"]},
                {"$inc": {"balance": -total_price}}
            )

        return jsonify({
            "waktu": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hasil": extracted_items,
            "total": total_price,
            "ocr_text": text
        })

    return jsonify({'error': 'Invalid file format'}), 400

@app.route('/upload/testing', methods=['POST'])
def upload_file_testing():
    if 'image' not in request.files:
        return jsonify({'error': 'No image part'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        npimg = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        # Preprocessing
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blur = cv2.GaussianBlur(gray, (5, 5), 0)
        thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]

        # OCR
        custom_config = r'--oem 3 --psm 6'
        text = pytesseract.image_to_string(thresh, config=custom_config)

        # Ekstraksi
        lines = text.splitlines()
        extracted_items = []
        pattern = re.compile(r'^(.*?)\s*[-:\s]\s*Rp?\s*([\d.,]+)$', re.IGNORECASE)

        for line in lines:
            line = line.strip()
            if not line:
                continue

            match = pattern.search(line)
            if match:
                nama_item = match.group(1).strip()
                harga_str = match.group(2).replace('.', '').replace(',', '.')

                if any(keyword in nama_item.lower() for keyword in ['total', 'metode', 'jumlah', 'bayar']):
                    continue

                try:
                    harga = float(harga_str)
                    extracted_items.append({
                        "nama": nama_item,
                        "harga": harga
                    })
                except ValueError:
                    continue

        total_price = sum(item['harga'] for item in extracted_items)

        return jsonify({
            "waktu": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hasil": extracted_items,
            "total": total_price,
            "ocr_text": text
        })

    return jsonify({'error': 'Invalid file format'}), 400


#   =====   RUN =====
if __name__ == "__main__":
    app.run(debug=True)
