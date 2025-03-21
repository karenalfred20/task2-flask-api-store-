from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, create_refresh_token
from dotenv import load_dotenv
from functools import wraps
from flask_migrate import Migrate
from flask_cors import CORS
from datetime import datetime, timedelta

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+mysqlconnector://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', '127.0.0.1')}/{os.getenv('DB_NAME', 'store_db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "supersecretkey")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=int(os.getenv("JWT_EXPIRY_MINUTES", 10)))
jwt = JWTManager(app)

from sqlalchemy import func

@app.before_request
def delete_old_tokens():
    threshold = datetime.utcnow() - timedelta(days=7)
    db.session.query(TokenBlocklist).filter(TokenBlocklist.created_at < threshold).delete()
    db.session.commit()


# Function to check if the token is revoked (blacklisted)
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return db.session.query(TokenBlocklist).filter_by(jti=jti).first() is not None


# User model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Product model
class Product(db.Model):
    __tablename__ = "products"
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    price = db.Column(db.Numeric(10,2), nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Token blacklist model
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route("/")
def home():
    return jsonify({"message": "API is running!"})



# User registration endpoint
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data or "name" not in data:
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already exists."}), 400

    hashed_password = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(name=data["name"], username=data["username"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

# User login endpoint
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get("username")).first()

    if not user or not bcrypt.checkpw(data["password"].encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({"error": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200

# Add new product (Admin only)
@app.route("/products", methods=["POST"])
@jwt_required()
def add_product():

    data = request.get_json()
    if not data or "pname" not in data or "price" not in data or "stock" not in data:
        return jsonify({"error": "Missing required fields"}), 400

    new_product = Product(
        pname=data["pname"],
        description=data.get("description", ""),
        price=data["price"],
        stock=data["stock"]
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({"message": "Product added successfully!"}), 201

# Get all products (Authenticated users)
@app.route("/products", methods=["GET"])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([
        {
            "pid": product.pid,
            "pname": product.pname,
            "description": product.description,
            "price": product.price,
            "stock": product.stock
        } for product in products
    ]), 200

# Get product by ID
@app.route("/products/<int:pid>", methods=["GET"])
@jwt_required()
def get_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({"error": "Product not found"}), 404
    return jsonify({
        "pid": product.pid,
        "pname": product.pname,
        "description": product.description,
        "price": product.price,
        "stock": product.stock
    }), 200

# Update product
@app.route("/products/<int:pid>", methods=["PUT"])
@jwt_required()
def update_product(pid):

    product = Product.query.get(pid)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    data = request.get_json()

    # Update product fields
    if "pname" in data:
        product.pname = data["pname"]
    if "description" in data:
        product.description = data["description"]
    if "price" in data:
        product.price = data["price"]
    if "stock" in data:
        product.stock = data["stock"]

    db.session.commit()
    return jsonify({"message": "Product updated successfully!"}), 200

# Delete a product
@app.route("/products/<int:pid>", methods=["DELETE"])
@jwt_required()
def delete_product(pid):

    product = Product.query.get(pid)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully!"}), 200

# Update user details (Authenticated users only)
@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def update_user(id):
    current_user_id = get_jwt_identity()

    # Check if the user is trying to update their own details
    if current_user_id != id:
        return jsonify({"error": "You can only update your own profile"}), 403

    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()

    # Validate and update user fields
    if "name" in data:
        user.name = data["name"]

    if "password" in data:
        hashed_password = bcrypt.hashpw(data["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = hashed_password

    db.session.commit()
    return jsonify({"message": "User details updated successfully!"}), 200

# User logout and token blacklist
@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()
    return jsonify({"message": "Successfully logged out"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
