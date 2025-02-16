from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash  # Updated import

# Initialize the Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'  # Used for sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Product model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    price = db.Column(db.Float, nullable=False)

# Login manager callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for home page (product page)
@app.route('/')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)

# Route for login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):  # Check hashed password
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your username and/or password.', 'danger')
    return render_template('login.html')

# Route for logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Route for adding a product (requires login)
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        new_product = Product(name=name, description=description, price=float(price))
        db.session.add(new_product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_product.html')

# Add a user to the database (for testing purposes)
with app.app_context():
    # Add a user with a hashed password
    if not User.query.filter_by(username='testuser').first():  # Prevent adding the user if already exists
        hashed_password = generate_password_hash('testpassword', method='pbkdf2:sha256')  # Fixed method
        user = User(username='testuser', password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print("User 'testuser' added to the database.")

# Run the app with context
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the database tables within the application context
    app.run(debug=True)
