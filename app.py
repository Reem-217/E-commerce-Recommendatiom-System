from flask import Flask, request, render_template,session, jsonify
import pandas as pd
import random
from flask_sqlalchemy import SQLAlchemy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from werkzeug.security import generate_password_hash, check_password_hash
import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
import hashlib
import os
app = Flask(__name__)

# load files===========================================================================================================
trending_products = pd.read_csv("models/trending_products.csv")
train_data = pd.read_csv("models/clean_data.csv")

# database configuration---------------------------------------
app.secret_key = "alskdjfwoeieiurlskdjfslkdjf"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@localhost/ecom"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Define your model class for the 'signup' table
class Signup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Define your model class for the 'signup' table
class Signin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)


# Recommendations functions============================================================================================
# Function to truncate product name
def truncate(text, length):
    if len(text) > length:
        return text[:length] + "..."
    else:
        return text


def content_based_recommendations(train_data, item_name, top_n=10):
    # Check if the item name exists in the training data
    if item_name not in train_data['Name'].values:
        print(f"Item '{item_name}' not found in the training data.")
        return pd.DataFrame()

    # Create a TF-IDF vectorizer for item descriptions
    tfidf_vectorizer = TfidfVectorizer(stop_words='english')

    # Apply TF-IDF vectorization to item descriptions
    tfidf_matrix_content = tfidf_vectorizer.fit_transform(train_data['Tags'])

    # Calculate cosine similarity between items based on descriptions
    cosine_similarities_content = cosine_similarity(tfidf_matrix_content, tfidf_matrix_content)

    # Find the index of the item
    item_index = train_data[train_data['Name'] == item_name].index[0]

    # Get the cosine similarity scores for the item
    similar_items = list(enumerate(cosine_similarities_content[item_index]))

    # Sort similar items by similarity score in descending order
    similar_items = sorted(similar_items, key=lambda x: x[1], reverse=True)

    # Get the top N most similar items (excluding the item itself)
    top_similar_items = similar_items[1:top_n+1]

    # Get the indices of the top similar items
    recommended_item_indices = [x[0] for x in top_similar_items]

    # Get the details of the top similar items
    recommended_items_details = train_data.iloc[recommended_item_indices][['Name', 'ReviewCount', 'Brand', 'ImageURL', 'Rating']]

    return recommended_items_details
# routes===============================================================================
# List of predefined image URLs
random_image_urls = [
    "static/img/img_1.png",
    "static/img/img_2.png",
    "static/img/img_3.png",
    "static/img/img_4.png",
    "static/img/img_5.png",
    "static/img/img_6.png",
    "static/img/img_7.png",
    "static/img/img_8.png",
]


@app.route("/")
def index():
    # Create a list of random image URLs for each product
    random_product_image_urls = [random.choice(random_image_urls) for _ in range(len(trending_products))]
    price = [40, 50, 60, 70, 100, 122, 106, 50, 30, 50]
    return render_template('index.html',trending_products=trending_products.head(8),truncate = truncate,
                           random_product_image_urls=random_product_image_urls,
                           random_price = random.choice(price))

@app.route("/main")
def main():
    username = session.get('username')
    content_based_rec = pd.DataFrame()  # or whatever default value you want
    return render_template('main.html', content_based_rec=content_based_rec, truncate=truncate)
    
    

# routes
@app.route("/index")
def indexredirect():
    username = session.get('username')
    # Create a list of random image URLs for each product
    random_product_image_urls = [random.choice(random_image_urls) for _ in range(len(trending_products))]
    price = [40, 50, 60, 70, 100, 122, 106, 50, 30, 50]
    return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                           random_product_image_urls=random_product_image_urls,
                           random_price=random.choice(price))
    
    
def hash_password(password):
    # Use a strong hashing algorithm like SHA-256
    salt = os.urandom(16)
    salted_password = salt + password.encode()
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt.hex() + hashed_password

def verify_password(stored_password, provided_password):
    # Extract salt from the stored password
    salt_hex = stored_password[:32]
    salt = bytes.fromhex(salt_hex)
    hashed_stored_password = stored_password[32:]

    # Hash the provided password with the same salt
    salted_password = salt + provided_password.encode()
    hashed_provided_password = hashlib.sha256(salted_password).hexdigest()
    
    return hashed_provided_password == hashed_stored_password    

@app.route("/signup", methods=['POST','GET'])
def signup():
    if request.method=='POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        random_product_image_urls = [random.choice(random_image_urls) for _ in range(len(trending_products))]
        price = [40, 50, 60, 70, 100, 122, 106, 50, 30, 50]
        # check if the username or email already exists
        existing_user=Signup.query.filter((Signup.username==username)|(Signup.email==email)).first()
        if existing_user:
            return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                               random_product_image_urls=random_product_image_urls, random_price=random.choice(price),signup_message='Username or email already exists!')
        #hash the password
        hashed_password=hash_password(password)
        new_signup = Signup(username=username, email=email, password=hashed_password)
        db.session.add(new_signup)
        db.session.commit()

        # Create a list of random image URLs for each product

        return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                               random_product_image_urls=random_product_image_urls, random_price=random.choice(price),
                               signup_message='User signed up successfully!'
                               )

@app.route('/signin', methods=['POST', 'GET'])
def signin():
    if request.method == 'POST':
        username = request.form['signinUsername']
        password = request.form['signinPassword']
        
        user = Signup.query.filter_by(username=username).first()
        # logging.debug(f'User: {user.username}')
        # logging.debug(f'Password: {password}')

        # Create a list of random image URLs for each product
        random_product_image_urls = [random.choice(random_image_urls) for _ in range(len(trending_products))]
        price = [40, 50, 60, 70, 100, 122, 106, 50, 30, 50]
        # logging.debug(check_password_hash(user.password, password))
        if user:
            # Check if the password matches
            logging.debug(f'Password: {user.password}')

            if verify_password(user.password, password):
                logging.debug('Password is correct')
                return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                                       random_product_image_urls=random_product_image_urls, random_price=random.choice(price),
                                       signup_message='User signed in successfully!')
            else:
                logging.debug('Password is incorrect')
                return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                                       random_product_image_urls=random_product_image_urls, random_price=random.choice(price),
                                       signup_message='Incorrect password!')
        else:
            return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                                   random_product_image_urls=random_product_image_urls, random_price=random.choice(price),
                                   signup_message='Username does not exist!')
    
    return render_template('index.html', trending_products=trending_products.head(8), truncate=truncate,
                           random_product_image_urls=random_product_image_urls, random_price=random.choice(price))
    

       
@app.route("/recommendations", methods=['POST', 'GET'])
def recommendations():
    content_based_rec = pd.DataFrame()  # Initialize an empty DataFrame by default

    if request.method == 'POST':
        prod = request.form.get('prod')
        nbr = int(request.form.get('nbr'))
        content_based_rec = content_based_recommendations(train_data, prod, top_n=nbr)

        if content_based_rec.empty:
            message = "No recommendations available for this product."
            return render_template('main.html', message=message, content_based_rec=content_based_rec)
        else:
            random_product_image_urls = [random.choice(random_image_urls) for _ in range(len(content_based_rec))]
            random_prices = [random.choice([40, 50, 60, 70, 100, 122, 106, 50, 30, 50]) for _ in range(len(content_based_rec))]

            content_based_rec['ImageURL'] = random_product_image_urls
            content_based_rec['Price'] = random_prices

    return render_template('main.html', content_based_rec=content_based_rec, truncate=truncate)

if __name__=='__main__':
    app.run(debug=True)