from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from dotenv import load_dotenv
import os
import requests
from flask import jsonify
from flask_mail import Mail, Message
import random
from datetime import date
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
from flask import send_file
from flask import request, jsonify
from openai import OpenAI
import numpy as np
from tensorflow import keras
from tensorflow.keras.preprocessing import image


# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'neurosole_secret'
# Simple admin credentials
ADMIN_USERNAME = "soumyo"
ADMIN_PASSWORD = "soumyo123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///neurosole.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY")) 
# Mail configuration (use your Gmail or app mail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'teamshop4insta@gmail.com'        # ⬅️ Replace
app.config['MAIL_PASSWORD'] = 'fleevwilfzqmeucz'      # ⬅️ Replace with Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'teamshop4insta@gmail.com'  # same as above

mail = Mail(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))
    signup_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_time = db.Column(db.DateTime)
    ip_address = db.Column(db.String(80))
    reset_attempts = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.Date, nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)



with app.app_context():
    db.create_all()
# Define and create upload folder
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load trained model
model = keras.models.load_model("foot_ulcer_classifier_recovered.keras")
print("✅ Ulcer model loaded successfully.")

@app.route('/')
def welcome():
    return render_template('welcome.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            user.last_login_time = datetime.utcnow()
            user.ip_address = request.remote_addr
            db.session.commit()
            session['user'] = user.email  # store session
            flash('Welcome back to NeuroSole!')
            return redirect(url_for('dashboard'))  # ⬅️ redirect to dashboard
        else:
            flash('Invalid credentials, please try again.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if User.query.count() >= 500:
            return "User limit reached!"
        
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Generate OTP
        otp = random.randint(100000, 999999)
        session['otp'] = str(otp)
        session['pending_user'] = {'name': name, 'email': email, 'password': password}

        # Send OTP via email
        msg = Message('NeuroSole Email Verification', recipients=[email])
        msg.body = f"Hi {name},\n\nYour NeuroSole verification code is: {otp}\n\nThank you!"
        mail.send(msg)

        flash('OTP sent to your email. Please verify.')
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')


# Prediction route
@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file:
        flash("No file uploaded")
        return redirect(url_for('dashboard'))

    # Save uploaded file
    upload_folder = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)

    # Preprocess the image for your Keras model
    img = image.load_img(file_path, target_size=(224, 224))  # adjust size to match your model
    img_array = image.img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)
    img_array = img_array / 255.0

    # Make predictions
    preds = model.predict(img_array)[0]

    # Example class mapping
    labels = ['Ulcered', 'Pre-Ulcer', 'Normal']
    probs = {label: float(preds[i]) for i, label in enumerate(labels)}
    top_index = np.argmax(preds)
    result = labels[top_index]
    confidence = round(float(preds[top_index]) * 100, 2)

    # Return the same dashboard with results
    return render_template(
        'index.html',      # or 'dashboard.html' if that’s your filename
        user=session.get('user'),
        image_url=os.path.join(upload_folder, file.filename),
        probs=probs,
        result=result,
        confidence=confidence
    )

@app.route('/test_chat')
def test_chat():
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Hello from NeuroSole!"}]
    )
    return response.choices[0].message.content


@app.route('/chat', methods=['POST'])
def chat():
    user_input = request.json.get('message', '').strip()
    if not user_input:
        return jsonify({"reply": "Please type a message."})

    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",  # safe, cheap, works with new keys
            messages=[
                {"role": "system", "content": "You are NeuroSole’s AI assistant. Be concise, polite, and helpful about diabetic foot ulcers and app guidance."},
                {"role": "user", "content": user_input}
            ]
        )
        reply = completion.choices[0].message.content
        return jsonify({"reply": reply})
    except Exception as e:
        # See the exact issue in terminal if something goes wrong
        print("Chatbot Error:", repr(e))
        return jsonify({"reply": "⚠️ The NeuroSole Assistant is temporarily offline."})

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))
@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if 'otp' in session and user_otp == session['otp']:
            data = session.pop('pending_user')
            hashed_pass = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            new_user = User(name=data['name'], email=data['email'], password=hashed_pass)
            db.session.add(new_user)
            db.session.commit()

            session.pop('otp', None)
            flash('Email verified! You can now log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Try again.')
            return redirect(url_for('verify_otp'))
    return render_template('verify.html')


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found.')
            return redirect(url_for('forgot'))

        # Reset limit logic
        today = date.today()
        if user.last_reset_date != today:
            user.last_reset_date = today
            user.reset_attempts = 0

        if user.reset_attempts >= 5:
            flash('Limit reached. Try again tomorrow.')
            db.session.commit()
            return redirect(url_for('forgot'))

        # Generate OTP
        otp = random.randint(100000, 999999)
        session['reset_otp'] = str(otp)
        session['reset_email'] = email

        # Send OTP email
        msg = Message('NeuroSole Password Reset', recipients=[email])
        msg.body = f"Your NeuroSole password reset OTP is: {otp}\n\nValid for 10 minutes."
        mail.send(msg)

        user.reset_attempts += 1
        db.session.commit()

        flash('OTP sent to your email.')
        return redirect(url_for('reset_password'))

    return render_template('forgot.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']

        if otp == session.get('reset_otp'):
            email = session.get('reset_email')
            user = User.query.filter_by(email=email).first()

            hashed_pass = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_pass
            db.session.commit()

            session.pop('reset_otp', None)
            session.pop('reset_email', None)
            flash('Password updated successfully! Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP.')
            return redirect(url_for('reset_password'))

    return render_template('reset.html')



@app.route('/download_report', methods=['POST'])
def download_report():
    # Retrieve prediction details from form or session
    result = request.form.get('result', 'Unknown')
    confidence = request.form.get('confidence', 'N/A')
    user = session.get('user', 'Anonymous')

    # Create PDF in memory
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)

    # --- Add Logo ---
    try:
        p.drawImage("static/logo.png", 50, 770, width=80, height=50)
    except:
        pass  # if logo missing, skip safely

    # --- Title ---
    p.setFont("Helvetica-Bold", 20)
    p.setFillColorRGB(0, 0.3, 0.7)
    p.drawString(150, 800, "NeuroSole Diagnostic Report")

    # --- User Info & Prediction ---
    p.setFont("Helvetica", 12)
    p.setFillColorRGB(0, 0, 0)
    p.drawString(50, 740, f"User Email: {user}")
    p.drawString(50, 720, f"Prediction Result: {result}")
    p.drawString(50, 700, f"Model Confidence: {confidence}")
    p.drawString(50, 680, f"Generated on: {datetime.now().strftime('%d %b %Y, %I:%M %p')}")

    # --- Signature ---
    p.setFont("Helvetica-Oblique", 11)
    p.setFillColorRGB(0.1, 0.1, 0.1)
    p.drawString(400, 100, "Digitally signed by")
    p.setFont("Helvetica-Bold", 13)
    p.drawString(400, 85, "Soumyo Mukherjee")
    p.setFont("Helvetica-Oblique", 10)
    p.drawString(400, 70, "Founder, NeuroSole")

    # Finalize page
    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="NeuroSole_Report.pdf",
        mimetype='application/pdf'
    )
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.')
    return render_template('admin_login.html')
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        flash('Please log in as admin.')
        return redirect(url_for('admin_login'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/update_location', methods=['POST'])
def update_location():
    if 'user' not in session:
        return '', 403
    data = request.get_json()
    user = User.query.filter_by(email=session['user']).first()
    if user:
        user.latitude = data.get('lat')
        user.longitude = data.get('lon')
        db.session.commit()
    return '', 200
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please log in first!')
        return redirect(url_for('login'))

    user_email = session['user']
    return render_template('index.html', user=user_email)


if __name__ == '__main__':
    app.run(debug=True)
