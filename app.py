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
from flask import jsonify

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

     # FIXED: Single votes table definition
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            vote INTEGER NOT NULL CHECK (vote IN (1, -1)),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(post_id, user_id),
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
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

    # User settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            bio TEXT,
            email_comments INTEGER DEFAULT 1,
            email_upvotes INTEGER DEFAULT 0,
            email_newsletter INTEGER DEFAULT 1,
            profile_public INTEGER DEFAULT 1,
            show_email INTEGER DEFAULT 0,
            allow_messages INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
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
                0,
                0
            ),
            (
                '@SecureNet',
                'New Zero-Day Exploit Found in Quantum Encryption',
                'A new zero-day exploit targeting quantum encryption breakthroughs has been identified. Experts are scrambling to patch the vulnerability before it can be widely used by malicious actors...',
                json.dumps(['#ZeroDay', '#Quantum', '#Exploit']),
                0,
                0
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


def get_user_id_by_username(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return row['id'] if row else None

def get_post_vote_counts(post_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM votes WHERE post_id = ? AND vote = 1', (post_id,))
    up = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM votes WHERE post_id = ? AND vote = -1', (post_id,))
    down = cursor.fetchone()[0]
    conn.close()
    return up, down

def get_user_vote_for_post(user_id, post_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT vote FROM votes WHERE user_id = ? AND post_id = ?', (user_id, post_id))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0  # 1, -1 or 0


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

def get_user_settings(user_id):
    """Get user settings, create default if not exists"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user_settings WHERE user_id = ?', (user_id,))
    settings = cursor.fetchone()
    
    if not settings:
        # Create default settings
        cursor.execute('''
            INSERT INTO user_settings (user_id) VALUES (?)
        ''', (user_id,))
        conn.commit()
        cursor.execute('SELECT * FROM user_settings WHERE user_id = ?', (user_id,))
        settings = cursor.fetchone()
    
    conn.close()
    return settings


def get_user_email(user_id):
    """Get user email"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result['email'] if result else ''


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


@app.route('/post/<int:post_id>/vote', methods=['POST'])
@login_required
def vote_post(post_id):
    """Handle upvote/downvote for a post"""
    vote_action = request.json.get('vote') if request.is_json else request.form.get('vote')
    if vote_action not in ('up', 'down'):
        return jsonify({'error': 'Invalid vote action'}), 400

    username = session.get('username')
    user_id = get_user_id_by_username(username)
    if user_id is None:
        return jsonify({'error': 'User not found'}), 403

    new_vote = 1 if vote_action == 'up' else -1

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Check existing vote
        cursor.execute('SELECT id, vote FROM votes WHERE user_id = ? AND post_id = ?', (user_id, post_id))
        existing = cursor.fetchone()

        if existing is None:
            # Insert new vote
            cursor.execute('INSERT INTO votes (post_id, user_id, vote) VALUES (?, ?, ?)',
                           (post_id, user_id, new_vote))
        else:
            existing_vote = existing['vote']
            if existing_vote == new_vote:
                # User clicked same vote again -> remove (unvote)
                cursor.execute('DELETE FROM votes WHERE id = ?', (existing['id'],))
            else:
                # Switch vote: update row
                cursor.execute('UPDATE votes SET vote = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?',
                               (new_vote, existing['id']))

        conn.commit()

        # Recalculate counts
        cursor.execute('SELECT COUNT(*) FROM votes WHERE post_id = ? AND vote = 1', (post_id,))
        up = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM votes WHERE post_id = ? AND vote = -1', (post_id,))
        down = cursor.fetchone()[0]

        # Update cached counts in posts table
        cursor.execute('UPDATE posts SET upvotes = ?, downvotes = ? WHERE id = ?', (up, down, post_id))
        conn.commit()

        # Get user's current vote state
        cursor.execute('SELECT vote FROM votes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
        row = cursor.fetchone()
        user_vote = row['vote'] if row else 0

        return jsonify({'upvotes': up, 'downvotes': down, 'user_vote': user_vote})
    except Exception as e:
        conn.rollback()
        print("Vote error:", e)
        return jsonify({'error': 'Server error'}), 500
    finally:
        conn.close()

    conn = get_db()

    cursor = conn.cursor()
    cursor.execute('SELECT upvotes, downvotes FROM posts WHERE id = ?', (post_id,))
    counts = cursor.fetchone()
    conn.close()

    up = counts['upvotes'] if counts else 0
    down = counts['downvotes'] if counts else 0

# If AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
        return jsonify({
            'status': 'success',
            'message': 'Vote processed.',
            'post_id': post_id,
            'upvotes': up,
            'downvotes': down
        }), 200

# fallback for normal POST (non-AJAX)
    return redirect(request.referrer or url_for('posts_page'))


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


@app.route('/profile')
@login_required
def profile_page():
    """
    Robust profile page:
      - works even if the `votes` table or the `value` column is missing
      - collects posts/comments counts, received up/down, votes given (if available)
      - top tags from user's posts and tags on posts the user voted on (if votes available)
      - recent posts
    """
    username = session.get('username')
    if not username:
        flash('User not found in session.', 'error')
        return redirect(url_for('login_page'))

    author_tag = f'@{username}'
    user_id = get_user_id_by_username(username)
    if user_id is None:
        flash('User record not found.', 'error')
        return redirect(url_for('login_page'))

    conn = get_db()
    cursor = conn.cursor()

    # Basic user info
    cursor.execute('SELECT username, email, created_at FROM users WHERE id = ?', (user_id,))
    user_row = cursor.fetchone()
    user_email = user_row['email'] if user_row and 'email' in user_row.keys() else None
    member_since = user_row['created_at'] if user_row and 'created_at' in user_row.keys() else None

    # Total posts by user
    cursor.execute('SELECT COUNT(*) AS cnt FROM posts WHERE author = ?', (author_tag,))
    total_posts = cursor.fetchone()['cnt'] or 0

    # Upvotes/downvotes received across their posts
    # Use IFNULL to be safe
    cursor.execute('SELECT IFNULL(SUM(upvotes), 0) AS up_recv, IFNULL(SUM(downvotes), 0) AS down_recv FROM posts WHERE author = ?', (author_tag,))
    recv_row = cursor.fetchone()
    upvotes_received = recv_row['up_recv'] if recv_row and 'up_recv' in recv_row.keys() else (recv_row[0] if recv_row else 0)
    downvotes_received = recv_row['down_recv'] if recv_row and 'down_recv' in recv_row.keys() else (recv_row[1] if recv_row else 0)

    # Total comments made by user
    cursor.execute('SELECT COUNT(*) AS cnt FROM comments WHERE author = ?', (author_tag,))
    comments_count = cursor.fetchone()['cnt'] or 0

    # Check whether votes table exists and whether it has a 'value' (or similar) column
    votes_table_exists = False
    votes_value_column = None
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='votes'")
        if cursor.fetchone():
            votes_table_exists = True
            # inspect columns
            cursor.execute("PRAGMA table_info(votes)")
            cols = cursor.fetchall()
            for c in cols:
                # row form: (cid, name, type, notnull, dflt_value, pk)
                colname = c[1] if isinstance(c, (list, tuple)) else c['name']
                if colname in ('value', 'vote', 'val'):
                    votes_value_column = colname
                    break
            # if not found, try to detect any integer-like column that might be vote
            if votes_value_column is None:
                for c in cols:
                    colname = c[1] if isinstance(c, (list, tuple)) else c['name']
                    # skip obvious id and fk columns
                    if colname in ('id', 'user_id', 'post_id', 'created_at'):
                        continue
                    # assume this column could be the vote column (best-effort)
                    votes_value_column = colname
                    break
    except Exception as e:
        # If any error occurs, treat as votes not available
        votes_table_exists = False
        votes_value_column = None

    # Default values
    upvotes_given = 0
    downvotes_given = 0
    top_tags_voted = []

    if votes_table_exists and votes_value_column:
        try:
            # Votes GIVEN by this user (count of rows where value==1 and value==-1)
            # we use parameterized SQL and compute using CASE so it works for integer vote values
            # note: if votes_value_column name is not 'value', inject it safely by using string
            col = votes_value_column
            # Build SQL dynamically but parameterize user_id
            sql = f'''
                SELECT
                  SUM(CASE WHEN {col} = 1 THEN 1 ELSE 0 END) AS up_given,
                  SUM(CASE WHEN {col} = -1 THEN 1 ELSE 0 END) AS down_given
                FROM votes WHERE user_id = ?
            '''
            cursor.execute(sql, (user_id,))
            given_row = cursor.fetchone()
            if given_row:
                # fetch by column name if available, else by index
                if isinstance(given_row, sqlite3.Row):
                    upvotes_given = given_row['up_given'] or 0
                    downvotes_given = given_row['down_given'] or 0
                else:
                    upvotes_given = given_row[0] or 0
                    downvotes_given = given_row[1] or 0
        except Exception as e:
            # if something goes wrong, keep zeros and continue
            print("Vote counts error:", e)
            upvotes_given = 0
            downvotes_given = 0

        try:
            # Top tags the user has voted ON (based on posts they voted on)
            cursor.execute(f'''
                SELECT p.tags as tags FROM posts p
                JOIN votes v ON p.id = v.post_id
                WHERE v.user_id = ?
            ''', (user_id,))
            rows = cursor.fetchall()
            tag_counts_voted = {}
            for r in rows:
                try:
                    tags = json.loads(r['tags']) if 'tags' in r.keys() else json.loads(r[0])
                    if isinstance(tags, list):
                        for t in tags:
                            tag_counts_voted[t] = tag_counts_voted.get(t, 0) + 1
                except Exception:
                    continue
            top_tags_voted = sorted(tag_counts_voted.items(), key=lambda x: x[1], reverse=True)[:3]
            top_tags_voted = [{'tag': t, 'count': c} for t, c in top_tags_voted]
        except Exception as e:
            print("Top tags voted error:", e)
            top_tags_voted = []
    else:
        # votes table not present or no vote column — safe fallbacks
        upvotes_given = 0
        downvotes_given = 0
        top_tags_voted = []

    # Top tags used in user's own posts
    cursor.execute('SELECT tags FROM posts WHERE author = ?', (author_tag,))
    rows = cursor.fetchall()
    tag_counts = {}
    for r in rows:
        try:
            tags = json.loads(r['tags']) if 'tags' in r.keys() else json.loads(r[0])
            if isinstance(tags, list):
                for t in tags:
                    tag_counts[t] = tag_counts.get(t, 0) + 1
        except Exception:
            # ignore malformed tags
            continue
    top_tags_posted = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    top_tags_posted = [{'tag': t, 'count': c} for t, c in top_tags_posted]

    # Recent posts by this user (last 5)
    cursor.execute('SELECT id, title, content, upvotes, downvotes, created_at, tags FROM posts WHERE author = ? ORDER BY created_at DESC LIMIT 5', (author_tag,))
    recent_rows = cursor.fetchall()
    recent_posts = []
    for r in recent_rows:
        recent_posts.append({
            'id': r['id'],
            'title': r['title'],
            'content': r['content'],
            'upvotes': r['upvotes'],
            'downvotes': r['downvotes'],
            'created_at': format_timestamp(r['created_at']),
            'tags': json.loads(r['tags']) if r['tags'] else []
        })

    conn.close()

    return render_template('profile.html',
                           username=username,
                           email=user_email,
                           member_since=member_since,
                           total_posts=total_posts,
                           upvotes_received=upvotes_received,
                           downvotes_received=downvotes_received,
                           comments_count=comments_count,
                           upvotes_given=upvotes_given,
                           downvotes_given=downvotes_given,
                           top_tags_posted=top_tags_posted,
                           top_tags_voted=top_tags_voted,
                           recent_posts=recent_posts)


@app.route('/settings')
@login_required
def settings_page():
    """Display settings page"""
    username = session.get('username')
    user_id = get_user_id_by_username(username)
    
    if not user_id:
        flash('User not found.', 'error')
        return redirect(url_for('login_page'))
    
    settings = get_user_settings(user_id)
    user_email = get_user_email(user_id)
    
    # Convert settings to dict for easier access in template
    notifications = {
        'email_comments': settings['email_comments'] if settings else 1,
        'email_upvotes': settings['email_upvotes'] if settings else 0,
        'email_newsletter': settings['email_newsletter'] if settings else 1
    }
    
    privacy = {
        'profile_public': settings['profile_public'] if settings else 1,
        'show_email': settings['show_email'] if settings else 0,
        'allow_messages': settings['allow_messages'] if settings else 1
    }
    
    user_bio = settings['bio'] if settings and settings['bio'] else ''
    
    return render_template('settings.html', 
                         user_email=user_email,
                         user_bio=user_bio,
                         notifications=notifications,
                         privacy=privacy)


@app.route('/settings/account', methods=['POST'])
@login_required
def update_account():
    """Update account information"""
    username = session.get('username')
    user_id = get_user_id_by_username(username)
    
    email = request.form.get('email', '').strip()
    bio = request.form.get('bio', '').strip()
    
    if not email:
        flash('Email is required.', 'error')
        return redirect(url_for('settings_page'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Update email in users table
        cursor.execute('UPDATE users SET email = ? WHERE id = ?', (email, user_id))
        
        # Update or insert bio in settings
        cursor.execute('SELECT id FROM user_settings WHERE user_id = ?', (user_id,))
        if cursor.fetchone():
            cursor.execute('UPDATE user_settings SET bio = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?', 
                         (bio, user_id))
        else:
            cursor.execute('INSERT INTO user_settings (user_id, bio) VALUES (?, ?)', (user_id, bio))
        
        conn.commit()
        flash('Account settings updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Email already in use by another account.', 'error')
    except Exception as e:
        print(f"Error updating account: {e}")
        flash('Failed to update account settings.', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('settings_page'))


@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    username = session.get('username')
    user_id = get_user_id_by_username(username)
    
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not all([current_password, new_password, confirm_password]):
        flash('All password fields are required.', 'error')
        return redirect(url_for('settings_page'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('settings_page'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters long.', 'error')
        return redirect(url_for('settings_page'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify current password
    cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    
    if not result or result['password'] != current_password:
        conn.close()
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('settings_page'))
    
    # Update password
    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (new_password, user_id))
    conn.commit()
    conn.close()
    
    flash('Password updated successfully!', 'success')
    return redirect(url_for('settings_page'))


@app.route('/settings/notifications', methods=['POST'])
@login_required
def update_notifications():
    """Update notification preferences"""
    username = session.get('username')
    user_id = get_user_id_by_username(username)
    
    email_comments = 1 if request.form.get('email_comments') else 0
    email_upvotes = 1 if request.form.get('email_upvotes') else 0
    email_newsletter = 1 if request.form.get('email_newsletter') else 0
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE user_settings 
            SET email_comments = ?, email_upvotes = ?, email_newsletter = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (email_comments, email_upvotes, email_newsletter, user_id))
        
        if cursor.rowcount == 0:
            # Create settings if not exists
            cursor.execute('''
                INSERT INTO user_settings (user_id, email_comments, email_upvotes, email_newsletter)
                VALUES (?, ?, ?, ?)
            ''', (user_id, email_comments, email_upvotes, email_newsletter))
        
        conn.commit()
        flash('Notification preferences updated!', 'success')
    except Exception as e:
        print(f"Error updating notifications: {e}")
        flash('Failed to update notification preferences.', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('settings_page'))


@app.route('/settings/privacy', methods=['POST'])
@login_required
def update_privacy():
    """Update privacy settings"""
    username = session.get('username')
    user_id = get_user_id_by_username(username)
    
    profile_public = 1 if request.form.get('profile_public') else 0
    show_email = 1 if request.form.get('show_email') else 0
    allow_messages = 1 if request.form.get('allow_messages') else 0
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE user_settings 
            SET profile_public = ?, show_email = ?, allow_messages = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (profile_public, show_email, allow_messages, user_id))
        
        if cursor.rowcount == 0:
            cursor.execute('''
                INSERT INTO user_settings (user_id, profile_public, show_email, allow_messages)
                VALUES (?, ?, ?, ?)
            ''', (user_id, profile_public, show_email, allow_messages))
        
        conn.commit()
        flash('Privacy settings updated!', 'success')
    except Exception as e:
        print(f"Error updating privacy: {e}")
        flash('Failed to update privacy settings.', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('settings_page'))


@app.route('/settings/delete-account')
@login_required
def delete_account():
    """Delete user account and all associated data"""
    username = session.get('username')
    user_id = get_user_id_by_username(username)
    author_tag = f'@{username}'
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Delete user's votes
        cursor.execute('DELETE FROM votes WHERE user_id = ?', (user_id,))
        
        # Delete user's comments
        cursor.execute('DELETE FROM comments WHERE author = ?', (author_tag,))
        
        # Delete user's posts
        cursor.execute('DELETE FROM posts WHERE author = ?', (author_tag,))
        
        # Delete user settings
        cursor.execute('DELETE FROM user_settings WHERE user_id = ?', (user_id,))
        
        # Delete verification codes
        conn_email = get_db()
        cursor_email = conn_email.cursor()
        cursor_email.execute('SELECT email FROM users WHERE id = ?', (user_id,))
        email_result = cursor_email.fetchone()
        if email_result:
            cursor.execute('DELETE FROM verification_codes WHERE email = ?', (email_result['email'],))
        conn_email.close()
        
        # Finally, delete the user
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        conn.commit()
        
        # Clear session
        session.clear()
        
        flash('Your account has been permanently deleted.', 'success')
        return redirect(url_for('posts_page'))
    except Exception as e:
        conn.rollback()
        print(f"Error deleting account: {e}")
        flash('Failed to delete account. Please try again.', 'error')
        return redirect(url_for('settings_page'))
    finally:
        conn.close()


        
if __name__ == '__main__':
    app.run(debug=True, port=5000)