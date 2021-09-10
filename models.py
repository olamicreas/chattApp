from app import db, bcrypt

class User(db.Model):
    __tablename__: 'user'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    username = db.Column(db.Text, unique=True)
    email = db.Column(db.String)
    password = db.Column(db.String)
    image = db.Column(db.String(150), default='img.jpg.png')

    def __init__(self, first_name, last_name, username, email, password):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('UTF_8')
