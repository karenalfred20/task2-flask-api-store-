from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt, create_refresh_token
)
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_cors import CORS
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+mysqlconnector://{os.getenv('DB_USER', 'root')}:"
    f"{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', '127.0.0.1')}/"
    f"{os.getenv('DB_NAME', 'store_db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "supersecretkey")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=int(os.getenv("JWT_EXPIRY_MINUTES", 10)))
jwt = JWTManager(app)

# Models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Product(db.Model):
    __tablename__ = "products"
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Authentication Routes(Signup)
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    hashed_password = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt())
    new_user = User(name=data["name"], username=data["username"], password=hashed_password.decode("utf-8"))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201
    
#Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.checkpw(data["password"].encode("utf-8"), user.password.encode("utf-8")):
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200
    return jsonify({"message": "Invalid credentials!"}), 401

# User Update Route (Protected)
@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def update_user(id):
    data = request.get_json()
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    if "name" in data:
        user.name = data["name"]
    db.session.commit()
    return jsonify({"message": "User updated successfully"})

# Product Routes (Require JWT).. Add a new product
@app.route("/products", methods=["POST"])
@jwt_required()
def add_product():
    data = request.get_json()
    new_product = Product(
        pname=data["pname"], description=data.get("description", ""),
        price=data["price"], stock=data["stock"]
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({"message": "Product added successfully!"}), 201

#Retrieve product
@app.route("/products", methods=["GET"])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([{ "pid": p.pid, "pname": p.pname, "price": float(p.price), "stock": p.stock } for p in products])

#Retrieve products
@app.route("/products/<int:pid>", methods=["GET"])
@jwt_required()
def get_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({"message": "Product not found"}), 404
    return jsonify({ "pid": product.pid, "pname": product.pname, "price": float(product.price), "stock": product.stock })
    
#Update product
@app.route("/products/<int:pid>", methods=["PUT"])
@jwt_required()
def update_product(pid):
    data = request.get_json()
    product = Product.query.get(pid)
    if not product:
        return jsonify({"message": "Product not found"}), 404
    if "pname" in data:
        product.pname = data["pname"]
    if "description" in data:
        product.description = data["description"]
    if "price" in data:
        product.price = data["price"]
    if "stock" in data:
        product.stock = data["stock"]
    db.session.commit()
    return jsonify({"message": "Product updated successfully!"})
    
#Delete product
@app.route("/products/<int:pid>", methods=["DELETE"])
@jwt_required()
def delete_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({"message": "Product not found"}), 404
    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully!"})

@app.route("/")
def home():
    return jsonify({"message": "API is running!"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0") 
