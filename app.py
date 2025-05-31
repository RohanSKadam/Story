from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import logging

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stories.db'  # For SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))  # Use a random secret key

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    stories = db.relationship('Story', backref='author', lazy=True)

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prompt = db.Column(db.String(255), nullable=False)
    story = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_story(prompt):
    # Placeholder for AI story generation logic
    return f"Once upon a time, in a land far away, there was a story about: {prompt}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    prompt = request.json.get('prompt')
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400
    story_text = generate_story(prompt)
    new_story = Story(prompt=prompt, story=story_text, user_id=current_user.id)
    db.session.add(new_story)
    db.session.commit()
    return jsonify({'story': story_text})

@app.route('/history', methods=['GET'])
@login_required
def get_history():
    stories = Story.query.filter_by(user_id=current_user.id).all()
    return jsonify({'history': [{'prompt': s.prompt, 'story': s.story} for s in stories]})

@app.route('/upload', methods=['POST'])
@login_required
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Validate file type
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        return jsonify({'error': 'Invalid file type. Only images are allowed.'}), 400

    uploads_dir = "uploads"
    os.makedirs(uploads_dir, exist_ok=True)
    filename = secure_filename(file.filename)
    file_path = os.path.join(uploads_dir, filename)
    file.save(file_path)
    logging.info(f'File uploaded: {file_path}')
    return jsonify({'message': 'File uploaded successfully', 'file_path': file_path})

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    hashed_password = generate_password_hash(password)  # Use default method
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User  registered successfully'})

if __name__ == '__main__':
    app.run(debug=True)
