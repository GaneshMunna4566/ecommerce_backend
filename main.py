import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
import bcrypt
import pymysql.cursors
import re
import smtplib
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
CORS(app)

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'ecommerce'

# Secret key for JWT
app.config['SECRET_KEY'] = 'your_secret_key'

# JWT configuration
app.config['JWT_TOKEN_LOCATION'] = ['headers']
jwt = JWTManager(app)

# Establishing connection to MySQL
try:
    connection = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    logging.info("Database connected successfully!")
except pymysql.Error as e:
    logging.error(f"Error connecting to database: {e}")

# Create upload folder if it doesn't exist
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Basic logging configuration
logging.basicConfig(level=logging.INFO)

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ping MySQL connection before consecutive execute() calls
def ping_mysql_connection():
    try:
        connection.ping(reconnect=True)
    except pymysql.Error as e:
        logging.error(f"Error pinging database: {e}")

# Route for registering a new user
@app.route('/signup', methods=['POST'])
def register():
    ping_mysql_connection()
    with connection.cursor() as cursor:
        data = request.json

        cursor.execute("SELECT * FROM users WHERE email = %s OR phone = %s", (data['email'], data['phone']))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'message': 'Email or phone already exists'}), 400

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', data['password']):
            return jsonify({'message': 'Password must be at least 8 characters long and contain symbols'}), 400

        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

        sql = "INSERT INTO users (email, phone, password, firstname, lastname) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(sql, (data['email'], data['phone'], hashed_password, data['firstname'], data['lastname']))
        connection.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Route for logging in a user
@app.route('/login', methods=['POST'])
def login():
    ping_mysql_connection()
    data = request.json

    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s", (data['email'],))
        user = cursor.fetchone()

        if user:
            if bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
                access_token = create_access_token(identity=user['email'])
                return jsonify({'message': 'Login successful', 'access_token': access_token}), 200
            else:
                return jsonify({'message': 'Incorrect password'}), 401
        else:
            return jsonify({'message': 'User not found'}), 404

# Route for requesting a password reset
@app.route('/reset_password', methods=['POST'])
def request_password_reset():
    ping_mysql_connection()
    email = request.json.get('email')

    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            reset_token = create_access_token(identity=email)

            success, error_message = send_reset_email(email, reset_token)

            if success:
                return jsonify({'message': 'Password reset email sent'}), 200
            else:
                return jsonify({'message': 'Failed to send password reset email', 'error': error_message}), 500
        else:
            return jsonify({'message': 'User not found'}), 404

# Function to send password reset email
def send_reset_email(user_email, reset_token):
    try:
        message = f"""
        To reset your password, click the following link:
        http://localhost:3000/updatepassword?token={reset_token}
        """
        msg = MIMEText(message)
        msg['Subject'] = 'Password Reset'
        msg['From'] = 'cheeraganesh1995@gmail.com'
        msg['To'] = user_email

        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login('cheeraganesh1995@gmail.com', 'arrg begf poyg alvn')

        smtp_server.sendmail('cheeraganesh1995@gmail.com', [user_email], msg.as_string())
        smtp_server.quit()

        return True, None
    except Exception as e:
        error_message = str(e)
        return False, error_message

# Route for updating password
@app.route('/update_password', methods=['POST'])
@jwt_required()
def update_password():
    ping_mysql_connection()
    email = get_jwt_identity()
    new_password = request.json.get('new_password')

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        connection.commit()

        if cursor.rowcount > 0:
            return jsonify({'message': 'Password updated successfully'}), 200
        else:
            return jsonify({'message': 'Failed to update password'}), 400

# Route for getting user profile
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    ping_mysql_connection()
    email = get_jwt_identity()

    with connection.cursor() as cursor:
        cursor.execute("SELECT id,firstname, lastname, email, phone FROM users WHERE email = %s", (email,))
        user_profile = cursor.fetchone()

        if user_profile:
            return jsonify(user_profile), 200
        else:
            return jsonify({'message': 'User not found'}), 404

# Route for updating a product
@app.route('/update_product/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            product_name = request.form.get('product_name')
            product_details = request.form.get('product_details')
            product_size = request.form.get('product_size')
            product_price = request.form.get('product_price')

            with connection.cursor() as cursor:
                # Check if the product belongs to the user
                cursor.execute("SELECT * FROM products WHERE id = %s AND user_id = %s", (product_id, user_id))
                product = cursor.fetchone()

                if product:
                    # Update the product details
                    sql = "UPDATE products SET product_name = %s, product_details = %s, product_size = %s, product_price = %s WHERE id = %s"
                    cursor.execute(sql, (product_name, product_details, product_size, product_price, product_id))
                    connection.commit()

                    return jsonify({'message': 'Product updated successfully'}), 200
                else:
                    return jsonify({'message': 'Product not found or does not belong to the user'}), 404
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for deleting a product
@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            with connection.cursor() as cursor:
                # Check if the product belongs to the user
                cursor.execute("SELECT * FROM products WHERE id = %s AND user_id = %s", (product_id, user_id))
                product = cursor.fetchone()

                if product:
                    # Delete the product
                    cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
                    connection.commit()

                    return jsonify({'message': 'Product deleted successfully'}), 200
                else:
                    return jsonify({'message': 'Product not found or does not belong to the user'}), 404
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/add_product', methods=['POST'])
@jwt_required()
def add_product():
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

            if user:
                user_id = user['id']

                product_name = request.form.get('product_name')
                product_details = request.form.get('product_details')
                product_size = request.form.get('product_size')
                product_price = request.form.get('product_price')

                if 'product_image' not in request.files:
                    return jsonify({'error': 'No file part'}), 400

                file = request.files['product_image']
                if file.filename == '':
                    return jsonify({'error': 'No selected file'}), 400

                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)

                    with connection.cursor() as cursor:
                        sql = "INSERT INTO products (user_id, product_name, product_details, product_size, product_price, image_path) VALUES (%s, %s, %s, %s, %s, %s)"
                        cursor.execute(sql, (user_id, product_name, product_details, product_size, product_price,
                                             filename))
                        connection.commit()

                    return jsonify({'message': 'Product added successfully'}), 201

                else:
                    return jsonify({'error': 'Invalid file format'}), 400
            else:
                return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Route for serving uploaded images
@app.route('/uploads/<path:filename>')
def serve_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route for getting products of a user
@app.route('/products', methods=['GET'])
@jwt_required()
def get_user_products():
    ping_mysql_connection()
    user_email = get_jwt_identity()

    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
        user = cursor.fetchone()

        if user:
            user_id = user['id']

            with connection.cursor() as cursor:
                sql = "SELECT * FROM products WHERE user_id = %s"
                cursor.execute(sql, (user_id,))
                products = cursor.fetchall()

            return jsonify(products), 200
        else:
            return jsonify({'message': 'User not found'}), 404


# Route for getting all products
@app.route('/all_products', methods=['GET'])
@jwt_required()
def get_all_products():
    try:
        ping_mysql_connection()
        with connection.cursor() as cursor:
            sql = "SELECT * FROM products"
            cursor.execute(sql)
            products = cursor.fetchall()

        return jsonify(products), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for adding an item to cart
@app.route('/add_to_cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        data = request.get_json()
        product_id = data['product_id']
        quantity = data['quantity']
        amount = data['amount']

        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            with connection.cursor() as cursor:
                sql = "INSERT INTO cart (user_id, product_id, quantity, amount) VALUES (%s, %s, %s, %s)"
                cursor.execute(sql, (user_id, product_id, quantity, amount))
                connection.commit()

            return jsonify({'message': 'Item added to cart successfully'}), 201
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for getting cart items
@app.route('/cart', methods=['GET'])
@jwt_required()
def get_cart_items():
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT c.*, p.product_name, p.product_price, p.image_path
                    FROM cart c
                    JOIN products p ON c.product_id = p.id
                    WHERE c.user_id = %s
                """, (user_id,))
                cart_items = cursor.fetchall()

            # Include 'id' property in the response
            formatted_cart_items = [{'id': item['id'], 'product_name': item['product_name'], 'product_price': item['product_price'], 'quantity': item['quantity'], 'amount': item['amount'], 'image_path': item['image_path']} for item in cart_items]

            return jsonify({'cart_items': formatted_cart_items}), 200
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for updating quantity and amount in the cart
@app.route('/update_cart_item/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_cart_item(item_id):
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        # Check if the user exists
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            # Check if the item belongs to the user
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM cart WHERE id = %s AND user_id = %s", (item_id, user_id))
                cart_item = cursor.fetchone()

                if cart_item:
                    # Extract new quantity and amount from the request data
                    data = request.json
                    new_quantity = data.get('quantity')
                    new_amount = data.get('amount')

                    # Update the cart item with new quantity and amount
                    with connection.cursor() as cursor:
                        cursor.execute("UPDATE cart SET quantity = %s, amount = %s WHERE id = %s", (new_quantity, new_amount, item_id))
                        connection.commit()

                    return jsonify({'message': 'Cart item updated successfully'}), 200
                else:
                    return jsonify({'message': 'Cart item not found or does not belong to the user'}), 404
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for deleting an item from cart
@app.route('/cart/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_cart_item(item_id):
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM cart WHERE id = %s AND user_id = %s", (item_id, user_id))
                connection.commit()

            return jsonify({'message': 'Item removed from cart successfully'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/subscriptions', methods=['POST'])
@jwt_required()
def create_subscription():
    try:
        # Retrieve user email from JWT token
        user_email = get_jwt_identity()

        # Retrieve user ID from the database based on email
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()
            if user:
                user_id = user['id']
            else:
                return jsonify({'error': 'User not found'}), 404

        # Check if a subscription already exists for the user
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM Subscription WHERE user_id = %s", (user_id,))
            existing_subscription = cursor.fetchone()
            if existing_subscription:
                return jsonify({'error': 'Subscription already exists for the user'}), 400

        # Extract other data from the request
        data = request.json
        card_name = data.get('card_name')
        card_number = data.get('card_number')
        card_exp_month = data.get('card_exp_month')
        card_exp_year = data.get('card_exp_year')
        card_cvv = data.get('card_cvv')

        # Insert data into the Subscription table
        with connection.cursor() as cursor:
            # Initially set status to 0
            sql = "INSERT INTO Subscription (user_id, card_name, card_number, card_exp_month, card_exp_year, card_cvv, status) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (user_id, card_name, card_number, card_exp_month, card_exp_year, card_cvv, 0))
            connection.commit()

        # After subscription creation, set status to 1
        with connection.cursor() as cursor:
            sql = "UPDATE Subscription SET status = %s WHERE user_id = %s"
            cursor.execute(sql, (1, user_id))
            connection.commit()

        return jsonify({'message': 'Subscription created successfully', 'status': 1}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for checkout
@app.route('/checkout', methods=['POST'])
@jwt_required()
def checkout():
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        # Retrieve user ID from the database based on email
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            # Retrieve cart items for the user
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT c.*, p.product_price
                    FROM cart c
                    JOIN products p ON c.product_id = p.id
                    WHERE c.user_id = %s
                """, (user_id,))
                cart_items = cursor.fetchall()

            if not cart_items:
                return jsonify({'message': 'Cart is empty'}), 400

            # Calculate total amount to be paid
            total_amount = sum(item['product_price'] * item['quantity'] for item in cart_items)

            # Collect checkout information from the request
            data = request.json
            address = data.get('address')
            state = data.get('state')
            city = data.get('city')
            postalcode = data.get('postalcode')
            card_number = data.get('card_number')
            card_exp_month = data.get('card_exp_month')
            card_exp_year = data.get('card_exp_year')
            card_cvv = data.get('card_cvv')

            # Insert checkout information into the database
            with connection.cursor() as cursor:
                sql = """
                    INSERT INTO checkout 
                    (user_id, product_id, amount, address, State, City, postalcode, card_number, card_exp_month, card_exp_year, card_cvv, status, total) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                for item in cart_items:
                    cursor.execute(sql, (
                        user_id,
                        item['product_id'],
                        item['product_price'],
                        address,
                        state,
                        city,
                        postalcode,
                        card_number,
                        card_exp_month,
                        card_exp_year,
                        card_cvv,
                        0,  # Assuming status 0 indicates the checkout is pending
                        total_amount
                    ))
                connection.commit()

            # Clear the user's cart after successful checkout
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
                connection.commit()

            return jsonify({'message': 'Checkout successful', 'total_amount': total_amount}), 200

        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/checkout_details', methods=['GET'])
@jwt_required()
def get_user_checkout_details():
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        # Retrieve user ID from the database based on email
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            # Retrieve checkout details for the user
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM checkout WHERE user_id = %s", (user_id,))
                checkout_details = cursor.fetchall()

            if checkout_details:
                return jsonify(checkout_details), 200
            else:
                return jsonify({'message': 'No checkout details found for the user'}), 404

        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/orders', methods=['GET'])
@jwt_required()
def get_user_orders():
    try:
        ping_mysql_connection()
        user_email = get_jwt_identity()

        # Retrieve user ID from the database based on email
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (user_email,))
            user = cursor.fetchone()

        if user:
            user_id = user['id']

            # Retrieve orders for the user along with product details
            with connection.cursor() as cursor:
                sql = """
                    SELECT c.*, p.product_name, p.product_details, p.product_size, p.product_price, p.image_path
                    FROM checkout c
                    JOIN products p ON c.product_id = p.id
                    WHERE c.user_id = %s
                """
                cursor.execute(sql, (user_id,))
                orders = cursor.fetchall()

            if orders:
                return jsonify(orders), 200
            else:
                return jsonify({'message': 'No orders found for the user'}), 404

        else:
            return jsonify({'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
