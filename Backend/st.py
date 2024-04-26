#Create a web “site” (interface, service) that allows a user to submit a file, such as a JPG, MP4, MOV,WAV,
#in any format (binary format) and a secret message (which may be text, an image, a movie, or any format/type) and you will “hide” that secret message “inside” the carrier file using steganography.
#Then you will “post” that file (if a picture, you can display it) on a publicly accessible web site.
#Your web service should have user authentication (if a user is submitting for steganography) but anyone
#(no authentication) may look at postings.

#Steganography Details:
#A user will give a “plaintext” file which may be of any format (P), and a message (M) that may also #be of any format, as well as several additional parameters including:
#(S) the starting bit number in P,
#(L) the length (actually the periodicity) of the replacement (in bits) (or L1 and L2 for different periodicities) (C) the chosen mode of operation.

#1. Given a message (M) which may be of any format (commonly a text, JPG, MPG, or similar) which will be the message we wish to “hide”.
#2. And, given a file (P) which will act as a carrier, one wishes to “embed” a message (M – the payload) by “modulating” (changing) the contents of the carrier (P).
#3. With the carrier (P) (this is the “plaintext” carrier) which is length LenP bits, a user wants to change every Lth bit, (where L is supplied by the user).
#Every Lth bit is replaced by successive bits from M, the message.
#4. Frequently, we wish to skip S bits at the beginning of P, because of the format or “type” of P (otherwise P will appear “corrupted”).
#5. A simple enhancement would allow L to change during processing (L = 8, then 16, then 28, then 8 again, etc.), which will be specified by the mode (C).
#6. Both the message (M) and the plaintext (P) may be of any format (commonly a JPG, MP4, OGG, MPG, AVI, MOV, WAV, DOC, text or similar)
#7. This process should be reversible, to be able to retrieve the original message.
#Web Service (Site): #Any users may view (or access) the modified files, but only authenticated users may submit the plaintext files, the “hidden” message, and associated information.


#backend code for the web service

from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from steganography.steganography import Steganography
import os

database_path = os.path.join(os.path.dirname(__file__), 'website.db')

db = SQLAlchemy()
app = Flask(__name__, template_folder='/Users/amangulati/Desktop/is2/templates')

secret_key = os.getenv('SECRET_KEY', default=os.urandom(16))
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}' #database path
db.init_app(app)

upload_folder = '/Users/amangulati/Desktop/is2/uploads'
app.config['UPLOAD_FOLDER'] =  upload_folder #upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'wav', 'bin', 'dat', 'raw'} #allowed file extensions
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Set a large enough limit (16MB)


login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)

def encode(file_path, message, starting_bit, length):
    # Convert the message to hexadecimal
    message_hex = message.encode('utf-8').hex()  # Convert the message to its hexadecimal representation
    message_bytes = bytes.fromhex(message_hex)  # Convert hexadecimal to bytes
    
    # Read the carrier file as binary data
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())  # Read the carrier file contents as a byte array
    
    # Insert the hexadecimal bytes into the carrier file
    byte_index = starting_bit  # Position to start embedding the message
    hex_index = 0
    while hex_index < len(message_bytes):
        if byte_index >= len(data):
            break  # Stop if we've reached the end of the carrier file
        
        # Replace the byte at the specified position with the message byte
        data[byte_index] = message_bytes[hex_index]
        hex_index += 1
        
        # Move to the next position based on the specified length
        byte_index += length
    
    # Save the modified carrier file
    with open(file_path, 'wb') as f:
        f.write(data)  # Write the modified data back to the carrier file



def decode(file_path, starting_bit, length):
    # Read the carrier file as binary data
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())  # Read the file contents as a byte array
    
    # Extract the hexadecimal bytes from the carrier file
    extracted_bytes = bytearray()  # To hold the extracted bytes
    byte_index = starting_bit
    while byte_index < len(data):
        extracted_bytes.append(data[byte_index])  # Extract the byte
        
        # Move to the next position based on the specified length
        byte_index += length
    
    # Convert the extracted bytes to text
    try:
        decoded_message = extracted_bytes.decode('utf-8', errors='replace')  # Convert bytes to text
    except Exception as e:
        decoded_message = f"Error decoding message: {e}"
    
    return decoded_message



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    #home page
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    #register page
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

#login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    #login page
    if request.method == 'POST':
        #get the username and password from the form
        username = request.form['username']
        password = request.form['password']

        #check if the user exists
        user = User.query.filter_by(username=username).first()

        #if the user does not exist
        if not user:
            flash('Username does not exist', 'error')
            return redirect(url_for('login'))

        #if the password is incorrect
        if not check_password_hash(user.password, password):
            flash('Password is incorrect', 'error')
            return redirect(url_for('login'))

        #if the user exists and the password is correct
        login_user(user)

        return redirect(url_for('upload'))

    return render_template('login.html')

#logout page
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

#upload page
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        #get the file and the message from the form
        file = request.files['file']
        message = request.form['message']
        starting_bit = int(request.form['starting_bit'])
        length = int(request.form['length'])
        mode = request.form['mode']

        #check if the file is empty
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload'))

        #check if the file extension is allowed
        #if file.filename.split('.')[-1] not in app.config['ALLOWED_EXTENSIONS']:
         #   flash('File extension not allowed', 'error')
          #  return redirect(url_for('upload'))

        #save the file
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        #encode the message in the file
        encode(os.path.join(app.config['UPLOAD_FOLDER'], filename), message, starting_bit, length)

        return redirect(url_for('view', filename=filename))

    return render_template('upload.html')

#view page
@app.route('/view/<filename>')
def view(filename):
    #provide an option to navigate to the decode page
    return render_template('view.html', filename=filename)


#download page
@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

#decode page
@app.route('/decode', methods=['GET', 'POST'])
@login_required
def decode_page():
    if request.method == 'POST':
        #get the file from the form
        file = request.files['file']

        #check if the file is empty
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('decode_page'))

        #check if the file extension is allowed
        #if file.filename.split('.')[-1] not in app.config['ALLOWED_EXTENSIONS']:
         #   flash('File extension not allowed', 'error')
          #  return redirect(url_for('decode_page'))

        #save the file
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        #get the starting bit and the length from the form
        starting_bit = int(request.form.get('starting_bit', 0))
        length = int(request.form.get('length', 8))
        mode = request.form.get('mode')

        #decode the message in the file
        message = decode(os.path.join(app.config['UPLOAD_FOLDER'], filename), starting_bit, length)

        return render_template('decoded.html', message=message)

    return render_template('decode.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)