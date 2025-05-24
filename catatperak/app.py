from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
import pytesseract
from PIL import Image
from datetime import timedelta

app = Flask(__name__)

#   =====   CONFIG  =====
app.config["JWT_SECRET_KEY"] = "catatkunci"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
client = MongoClient("mongodb://localhost:27017/")
db = client["ocr_finance_db"]
jwt = JWTManager(app)


#   =====   PAGE    =====
@app.route("/")
def landing_page():
    return render_template("index.html")

#   =====   UTILS   =====
def user_schema(user):
    return {"id": str(user["_id"]), "username": user["username"], "role": user["role"]}

def transaction_schema(txn):
    return {
        "id": str(txn["_id"]),
        "user_id": str(txn["user_id"]),
        "type": txn["type"],
        "name": txn["name"],
        "item": txn["item"],
        "price": txn["price"],
        "account": txn["account"],
        "note": txn.get("note", ""),
        "date": txn["date"]
    }

def account_schema(acc):
    return {"id": str(acc["_id"]), "user_id": str(acc["user_id"]), "name": acc["name"], "balance": acc["balance"]}

def extract_text_from_image(path):
    img = Image.open(path)
    return pytesseract.image_to_string(img)

#   =====   UTILS: Admin Check  =====
def is_admin(user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    return user and user.get("role") == "admin"

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

#   =====   ADMIN LOGIN PAGE    =====
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = db.users.find_one({"username": username})
        if user and user.get("role") == "admin" and check_password_hash(user["password"], password):
            session["admin_id"] = str(user["_id"])
            session["admin_username"] = user["username"]
            return redirect(url_for("admin_dashboard"))
        else:
            return render_template("admin_login.html", error="Login gagal. Coba lagi.")

    return render_template("admin_login.html")

#   =====   ADMIN DASHBOARD   =====
@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    return render_template("admin_dashboard.html", username=session["admin_username"])

#   =====   ADMIN LOGOUT    =====
@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


#   =====   AUTH    =====
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    # Validasi input kosong
    if not all([username, email, password, confirm_password]):
        return jsonify({"msg": "Semua field wajib diisi"}), 400

    # Password cocok?
    if password != confirm_password:
        return jsonify({"msg": "Password dan konfirmasi tidak cocok"}), 400

    # Cek email & username
    if db.users.find_one({"username": username}):
        return jsonify({"msg": "Username sudah terdaftar"}), 400

    if db.users.find_one({"email": email}):
        return jsonify({"msg": "Email sudah terdaftar"}), 400

    # Simpan user
    user = {
        "username": username,
        "email": email,
        "password": generate_password_hash(password),
        "role": "user"
    }
    db.users.insert_one(user)
    return jsonify({"msg": "Registrasi berhasil"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = db.users.find_one({"username": data["username"]})
    if not user or not check_password_hash(user["password"], data["password"]):
        return jsonify({"msg": "Username atau password salah"}), 401
    token = create_access_token(identity=str(user["_id"]))
    return jsonify({"access_token": token})

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

    db.accounts.update_one({"_id": ObjectId(acc_id)}, {"$set": {"name": data["name"]}})
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
    txn = {
        "user_id": ObjectId(user_id),
        "type": data["type"],  # income / expense
        "name": data["name"],
        "item": data["item"],
        "price": data["price"],
        "account": data["account"],
        "note": data.get("note", ""),
        "date": datetime.now()
    }
    db.transactions.insert_one(txn)

    # Update account balance    
    acc = db.accounts.find_one({"user_id": ObjectId(user_id), "name": data["account"]})
    if acc:
        new_balance = acc["balance"] + data["price"] if data["type"] == "income" else acc["balance"] - data["price"]
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
        adj = txn["price"] if txn["type"] == "income" else -txn["price"]
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
@app.route("/ocr", methods=["POST"])
def ocr_upload():
    if "image" not in request.files:
        return jsonify({"msg": "No image file"}), 400
    image = request.files["image"]
    path = f"temp_{datetime.now().timestamp()}.jpg"
    image.save(path)
    text = extract_text_from_image(path)
    return jsonify({"text": text})

#   =====   RUN =====
if __name__ == "__main__":
    app.run(debug=True)
