from flask import Flask, request, jsonify, Blueprint
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from datetime import timedelta
from dotenv import load_dotenv
import os

load_dotenv()




#
app = Flask(__name__)

# Set MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'task_db'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)



# Set JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'

# Set MySQL و JWT
mysql = MySQL(app)
jwt = JWTManager(app)

# Blueprint For Authentication
auth_bp = Blueprint('auth', __name__)

#Signup
@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (data['username'],))
    existing_user = cursor.fetchone()

    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400

    cursor.execute("INSERT INTO users (name, username, password) VALUES (%s, %s, %s)",
                   (data['name'], data['username'], hashed_pw))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'User registered successfully'}), 201

#Login
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, password FROM users WHERE username = %s", (data['username'],))
    user = cursor.fetchone()
    cursor.close()

    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[1].encode()):

        token = create_access_token(identity=str(user[0]))
        return jsonify({'token': token}), 200

    return jsonify({'message': 'Invalid credentials'}), 401

#Update user by id
@auth_bp.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user = get_jwt_identity()
    if str(current_user) != str(id):
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.json

    if 'password' in data:
        return jsonify({'message': 'Cannot change password here'}), 400

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE users SET name = %s, username = %s WHERE id = %s",
                   (data['name'], data['username'], id))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'User updated successfully'}), 200




# Blueprint
product_bp = Blueprint('product', __name__)

#Add a product
@product_bp.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.json
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO products (pname, description, price, stock, created_at) VALUES (%s, %s, %s, %s, NOW())",
               (data['pname'], data['description'], data['price'], data['stock']))

    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Product added successfully'}), 201

#Get all products
@product_bp.route('/products', methods=['GET'])
def get_products():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()
    product_list = []
    for product in products:
        product_list.append({
            'pid': product[0],
            'pname': product[1],
            'description': product[2],
            'price': product[3],
            'stock': product[4],
            'created_at': product[5].strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(product_list)

#Get a product
@product_bp.route('/products/<int:pid>', methods=['GET'])
def get_product(pid):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM products WHERE pid = %s", (pid,))
    product = cursor.fetchone()
    cursor.close()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    return jsonify({
        'pid': product[0],
        'pname': product[1],
        'description': product[2],
        'price': product[3],
        'stock': product[4],
        'created_at': product[5].strftime('%Y-%m-%d %H:%M:%S')
    })

#Update a product
@product_bp.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.json
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE products SET pname = %s, description = %s, price = %s, stock = %s WHERE pid = %s",
                   (data['pname'], data['description'], data['price'], data['stock'], pid))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Product updated successfully'}), 200

#Delete a product
@product_bp.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM products WHERE pid = %s", (pid,))
    mysql.connection.commit()
    cursor.close()
    return jsonify({'message': 'Product deleted successfully'}), 200

#
app.register_blueprint(auth_bp)
app.register_blueprint(product_bp)

# Activate app
if __name__ == "__main__":
    app.run(debug=True)
