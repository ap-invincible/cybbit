from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime, timedelta
import json
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import base64
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this!


# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Database setup
DATABASE = 'forum.db'

def get_db():
    """Create a database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Posts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image_path TEXT,
            tags TEXT NOT NULL,
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')    
    
    # Comments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')

    # Verification codes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0
        )
    ''')
    
    # Check if posts table is empty and add sample posts
    cursor.execute('SELECT COUNT(*) as count FROM posts')
    if cursor.fetchone()['count'] == 0:
        sample_posts = [
            (
                '@CyberGuardian',
                'Critical Vulnerability Found in Major SSL Library',
                'Researchers have discovered a critical vulnerability in OpenSSL that could affect millions of websites worldwide. The flaw, designated as CVE-2024-XXXX, allows attackers to bypass encryption protocols...',
                json.dumps(['#OpenSSL', '#Vulnerability', '#Security']),
                159,
                14
            ),
            (
                '@SecureNet',
                'New Zero-Day Exploit Found in Quantum Encryption',
                'A new zero-day exploit targeting quantum encryption breakthroughs has been identified. Experts are scrambling to patch the vulnerability before it can be widely used by malicious actors...',
                json.dumps(['#ZeroDay', '#Quantum', '#Exploit']),
                102,
                9
            )
        ]
        
        cursor.executemany('''
            INSERT INTO posts (author, title, content, tags, upvotes, downvotes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', sample_posts)
    
    conn.commit()
    conn.close()

def send_verification_email(email, code):
    """Send verification code via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = email
        msg['Subject'] = 'CyberPulse - Email Verification Code'
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0f1419; color: #e4e6eb; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1a2332; border-radius: 8px; padding: 30px; border: 1px solid #2d3748;">
                <h1 style="color: #ffffff; margin-bottom: 20px;">Welcome to CyberPulse!</h1>
                <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                    Thank you for registering. Please use the verification code below to complete your registration:
                </p>
                <div style="background-color: #374151; padding: 20px; border-radius: 6px; text-align: center; margin: 30px 0;">
                    <h2 style="color: #60a5fa; font-size: 36px; letter-spacing: 8px; margin: 0;">{code}</h2>
                </div>
                <p style="font-size: 14px; color: #9ca3af; margin-top: 20px;">
                    This code will expire in 10 minutes. If you didn't request this code, please ignore this email.
                </p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_ADDRESS = 'noreply.cyberpulse@gmail.com'
EMAIL_PASSWORD = 'blhp gwnv yzpg hgnc'

def generate_verification_code():
    """Generate 4-digit verification code"""
    return str(random.randint(1000, 9999))

def save_verification_code(email, code):
    """Save verification code to database"""
    conn = get_db()
    cursor = conn.cursor()
    expires_at = datetime.now() + timedelta(minutes=10)
    cursor.execute('INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)',
                   (email, code, expires_at))
    conn.commit()
    conn.close()

def verify_code(email, code):
    """Verify the code provided by user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM verification_codes 
        WHERE email = ? AND code = ? AND used = 0 AND expires_at > ?
        ORDER BY id DESC LIMIT 1
    ''', (email, code, datetime.now()))
    result = cursor.fetchone()
    
    if result:
        cursor.execute('UPDATE verification_codes SET used = 1 WHERE id = ?', (result['id'],))
        conn.commit()
        conn.close()
        return True
    
    conn.close()
    return False

def username_exists(username):
    """Check if username already exists"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def email_exists(email):
    """Check if email already exists"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def user_exists(identifier):
    """Check if user exists by username or email"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    return user is not None


def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to perform this action.', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def get_all_posts():
    """Fetch all posts from database"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM posts ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    
    posts = []
    for row in rows:
        # Get all column names
        columns = row.keys()
        
        posts.append({
            'id': row['id'],
            'author': row['author'],
            'title': row['title'],
            'content': row['content'],
            'tags': json.loads(row['tags']),
            'upvotes': row['upvotes'],
            'downvotes': row['downvotes'],
            'timestamp': format_timestamp(row['created_at'])
        })
    
    return posts


def get_post_by_id(post_id):
    """Fetch a single post by ID"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM posts WHERE id = ?', (post_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            'id': row['id'],
            'author': row['author'],
            'title': row['title'],
            'content': row['content'],
            'image_path': row['image_path'] if 'image_path' in row.keys() else None,
            'tags': json.loads(row['tags']),
            'upvotes': row['upvotes'],
            'downvotes': row['downvotes'],
            'timestamp': format_timestamp(row['created_at'])
        }
    return None

def get_comments_for_post(post_id):
    """Fetch all comments for a specific post"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC', (post_id,))
    rows = cursor.fetchall()
    conn.close()
    
    comments = []
    for row in rows:
        comments.append({
            'id': row['id'],
            'author': row['author'],
            'content': row['content'],
            'timestamp': format_timestamp(row['created_at'])
        })
    
    return comments

def add_comment(post_id, author, content):
    """Add a new comment to a post"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO comments (post_id, author, content)
        VALUES (?, ?, ?)
    ''', (post_id, author, content))
    conn.commit()
    conn.close()

def format_timestamp(timestamp):
    """Format timestamp to relative time"""
    try:
        # Handle both string and datetime objects
        if isinstance(timestamp, str):
            post_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        else:
            post_time = timestamp
            
        now = datetime.now()
        diff = now - post_time
        
        # Calculate total seconds for more accurate time differences
        total_seconds = diff.total_seconds()
        
        if total_seconds < 60:
            return 'Just now'
        elif total_seconds < 3600:  # Less than 1 hour
            minutes = int(total_seconds // 60)
            return f'{minutes} minute{"s" if minutes > 1 else ""} ago'
        elif total_seconds < 86400:  # Less than 1 day
            hours = int(total_seconds // 3600)
            return f'{hours} hour{"s" if hours > 1 else ""} ago'
        elif diff.days < 30:
            return f'{diff.days} day{"s" if diff.days > 1 else ""} ago'
        else:
            return post_time.strftime('%b %d, %Y')
    except Exception as e:
        print(f"Timestamp error: {e}")
        return timestamp

def add_post(author, title, content, tags, image_path=None):
    """Add a new post to database"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO posts (author, title, content, image_path, tags, upvotes, downvotes)
        VALUES (?, ?, ?, ?, ?, 0, 0)
    ''', (author, title, content, image_path, json.dumps(tags)))
    
    conn.commit()
    conn.close()

def create_user(username, email, password):
    """Create a new user"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                       (username, email, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def verify_login(identifier, password):
    """Verify user login with username or email"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE (username = ? OR email = ?) AND password = ?',
                   (identifier, identifier, password))
    user = cursor.fetchone()
    conn.close()
    return user

# Initialize database when app starts
with app.app_context():
    init_db()

@app.route('/')
def home():
    return redirect(url_for('posts_page'))

@app.route('/posts')
def posts_page():
    posts = get_all_posts()
    return render_template('posts.html', posts=posts)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = get_post_by_id(post_id)
    if not post:
        flash('Post not found.', 'error')
        return redirect(url_for('posts_page'))
    
    comments = get_comments_for_post(post_id)
    return render_template('view_post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment_to_post(post_id):
    content = request.form.get('content')
    if content and content.strip():
        author = f"@{session['username']}"
        add_comment(post_id, author, content.strip())
        flash('Comment added successfully!', 'success')
    else:
        flash('Comment cannot be empty.', 'error')
    
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/create')
def create_page():
    return render_template('create.html')

@app.route('/create-post', methods=['POST'])
def create_post():
    author = request.form.get('author')
    title = request.form.get('title')
    content = request.form.get('content')
    tags_input = request.form.get('tags', '')
    image_data = request.form.get('image_data')
    image_position = request.form.get('image_position')
    
    # Handle image if provided
    image_path = None
    if image_data and image_data.startswith('data:image'):
        try:
            # Extract image format and data
            header, encoded = image_data.split(',', 1)
            image_format = header.split(';')[0].split('/')[1]
            
            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"post_{timestamp}.{image_format}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Decode and save image
            import base64
            image_bytes = base64.b64decode(encoded)
            with open(filepath, 'wb') as f:
                f.write(image_bytes)
            
            image_path = f"uploads/{filename}"
        except Exception as e:
            print(f"Image upload error: {e}")
            flash('Failed to upload image. Post created without image.', 'error')
    
    # Process tags
    tags = [tag.strip() for tag in tags_input.split(',') if tag.strip()]
    if not tags:
        tags = ['#General']
    
    # Add @ to author if not present
    if not author.startswith('@'):
        author = f'@{author}'
    
    # Content already has [IMAGE] marker at the right position from frontend
    # Replace [IMAGE] with [IMAGE_HERE] for backend processing
    if image_path and '[IMAGE]' in content:
        content = content.replace('[IMAGE]', '[IMAGE_HERE]')
    
    # Save to database
    add_post(author, title, content, tags, image_path)
    
    flash('Post created successfully!', 'success')
    return redirect(url_for('posts_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '').strip()
        
        # Check if user exists first
        if not user_exists(identifier):
            flash('This user is not registered. Would you like to create an account?', 'error')
            return render_template('login.html', show_register_prompt=True)
        
        # Verify password
        user = verify_login(identifier, password)
        if user:
            session['username'] = user['username']
            flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('posts_page'))
        else:
            flash('Incorrect password. Please try again.', 'error')
            return render_template('login.html')
    
    return render_template('login.html', show_register_prompt=False)

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        step = request.form.get('step', '1')
        
        if step == '1':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            
            if not username or not email:
                flash('Username and email are required.', 'error')
                return render_template('register.html', step=1)
            
            if username_exists(username):
                flash('This username is already registered. Please choose a different username.', 'error')
                return render_template('register.html', step=1)
            
            if email_exists(email):
                flash('This email address is already registered. Please use a different email or login.', 'error')
                return render_template('register.html', step=1)
            
            code = generate_verification_code()
            save_verification_code(email, code)
            
            if send_verification_email(email, code):
                session['temp_username'] = username
                session['temp_email'] = email
                flash('Verification code sent to your email!', 'success')
                return render_template('register.html', step=2, email=email)
            else:
                flash('Failed to send verification email. Please try again.', 'error')
                return render_template('register.html', step=1)
        
        elif step == '2':
            code = request.form.get('code', '').strip()
            email = session.get('temp_email')
            
            if verify_code(email, code):
                flash('Email verified! Please create your password.', 'success')
                return render_template('register.html', step=3)
            else:
                flash('Invalid or expired verification code. Please try again.', 'error')
                return render_template('register.html', step=2, email=email)
        
        elif step == '3':
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            username = session.get('temp_username')
            email = session.get('temp_email')
            
            if not password or not confirm_password:
                flash('Please enter both password fields.', 'error')
                return render_template('register.html', step=3)
            
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('register.html', step=3)
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return render_template('register.html', step=3)
            
            if create_user(username, email, password):
                session.pop('temp_username', None)
                session.pop('temp_email', None)
                flash('Registration successful! Please login with your credentials.', 'success')
                return redirect(url_for('login_page'))
            else:
                flash('Registration failed. Please try again.', 'error')
                return render_template('register.html', step=3)
    
    return render_template('register.html', step=1)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('posts_page'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)