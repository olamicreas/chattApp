from flask import Flask, render_template, request, flash, redirect, url_for, session, abort, jsonify
from werkzeug import datastructures
from flask_msearch import Search 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_uploads import IMAGES, configure_uploads, patch_request_class, UploadSet
from forms import RegistrationForm, LoginForm, MessageForm, RoomForm
from flask_socketio import SocketIO, emit, Namespace
from flask_moment import Moment
from uuid import uuid4
import random, string
from sqlalchemy import exists, case, distinct
from datetime import datetime
import os, secrets
import json

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
moment = Moment(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
login_manager = LoginManager()
search = Search()
login_manager.init_app(app)
search.init_app(app)
login_manager.login_view='login'
login_manager.needs_refresh_messsage_category='danger'
login_manager.login_message=u'Please login first'


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://olamicreas:mujeeb@localhost/storage'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['UPLOADED_PHOTOS_DEST'] = os.path.join(basedir, 'static/images')


moment.init_app(app)
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
patch_request_class(app)


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


#Random string generator used for message and thread ID's
def randstrurl(type, pmthread=None):
	letters = string.ascii_lowercase
	randstr =  ''.join(random.choice(letters) for i in range(8))

	if pmthread:
		if not db.session.query(exists().where(Message.thread_id == randstr)).scalar():
			return randstr
		else:
			randstrurl(type=Message, pmthread=True)

	if not db.session.query(exists().where(type.url == randstr)).scalar():
		return randstr
	else:
		randstrurl(type=type)
############



class User(db.Model, UserMixin):

	__tablename__ : 'user'
	__searchable__ = ['username']

	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String)
	last_name = db.Column(db.String)
	username = db.Column(db.Text, unique=True)
	email = db.Column(db.String)
	PhoneNo = db.Column(db.String(150), unique=True)
	password = db.Column(db.String)
	websocket_id = db.Column(db.String, unique=True, index=True)

	image = db.Column(db.String(150), nullable=False, default='img.jpg.png')
    

	def __init__(self, first_name, last_name, username, email, PhoneNo, password, image):
		self.first_name = first_name
		self.last_name = last_name
		self.username = username
		self.email = email
		self.PhoneNo = PhoneNo
		self.password = bcrypt.generate_password_hash(password).decode('UTF_8')
		self.image = image

	@classmethod
	def authenticate(cls, username, password):

		found_user = cls.query.filter_by(username = username).first()
		if found_user:
			authenticate_user = bcrypt.check_password_hash(found_user.password, password)
			if authenticate_user:
				return found_user
            
		return False


class Message(db.Model):


    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String())
    subject = db.Column(db.String())
    sender_id = db.Column(db.String())
    recipient_id = db.Column(db.String())
    body = db.Column(db.String())
    timestamp = db.Column(db.DateTime, index=True)
    read = db.Column(db.Boolean, default=False)
    thread_id = db.Column(db.String())
    sender_del = db.Column(db.Boolean())
    recipient_del = db.Column(db.Boolean())
    

    def __repr__(self):
       return '<Message %r' % self.body
        

class Rooms(db.Model):

    __tablename__: 'rooms'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    description = db.Column(db.String)

    def __init__(self, name, description):
        self.name = name
        self.description = description 

   


@app.route('/registeration', methods=["GET", "POST"])

def registeration():
	form = RegistrationForm(request.form)
	if request.method == 'POST':

		try:
        
                
			first_name = form.first_name.data
			last_name = form.last_name.data
			username = form.username.data.lower()
			PhoneNo = form.PhoneNo.data
			email = form.email.data
			password = form.password.data
			image = photos.save(request.files.get('image'), name=secrets.token_hex(10) + ".")
			json.dumps(image)           

			new_user = User(first_name=first_name, last_name=last_name, username=username, PhoneNo=PhoneNo, email=email, password=password, image=image)
						
			db.session.add(new_user)
			db.session.commit()
			flash(f'Registration Successful', 'success')
			return redirect(url_for('login'))

		except Exception as e:
			flash(f'Username or email has already been taken', 'danger')
			print(e)
       

    


       
                   
        

       
	return render_template('user/register.html', form=form)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)

        
    if request.method == 'POST':
      

        usersAuth = User.authenticate(form.username.data, form.password.data)
        user = User.query.filter_by(username=form.username.data).first()
        
    
        try:

            if user:
                if usersAuth:

                    login_user(user)
                    flash(f'You are now logged in', 'success')
                    next = request.args.get('next')
                    return redirect(next or url_for('index'))
        
                else:
                    flash(f'incorrect password or username', 'danger')
            else:
                flash(f'You are yet to register or your log in details are incorrect', 'danger')         
        except Exception as e:
            print(e)
            flash(f'Omo Wahala don sup ooo', 'danger')
            
            
            
        
        

    

    return render_template('user/login.html', form=form)





@app.route('/')
def home():
  
	

    return render_template('user/home.html')


@app.route('/index')
@login_required
def index():
    users = User.query.all()
    
    room =  Rooms.query.all()
    

    return render_template('user/index.html', users=users, room=room)





@app.route('/profile/<int:id>')
def profile(id):
    
    user = User.query.get(id)

    
    return render_template('user/profile.html', user=user)

@app.route('/personal')
def personal():
    if current_user.is_authenticated:
        username = current_user.username
        email = current_user.email
        image = current_user.image
        json.dumps(image)
        
        return render_template('user/personal.html', username=username, email=email, image=image)
    else:
        flash(f'An error occured')


@app.route('/logout')
def logout():
    logout_user()
    flash(f'You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/chatting/<recipient>/<author>/', methods=['POST', 'GET'])
@login_required
def chatting(recipient, author):

    author = current_user
    user = User.query.filter_by(username=recipient).first()
    form = MessageForm(request.form)
    
    if request.method == 'POST':
        
        
        new_msg = Message(content=form.content.data, recipient=user, author=author)
        db.session.add(new_msg)
        db.session.commit()
        flash(f'Your message has been sent to {recipient}', 'success')
        return redirect(url_for('chatting', recipient=recipient, author=current_user.username))

    
            
    return render_template('user/message.html', form=form, recipient=recipient, user=user, author=author)
@app.route('/messages/', methods=['POST', 'GET'])
@login_required
def messages():


	if request.args.get('thread_id'):

		#Thread ownership security check
		if not db.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.recipient_id == current_user.username) \
		or not db.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.sender_id == current_user.username):
			abort(404)
		##########

		#Fetches non deleted messages in the thread for the current user.
		message_thread_sender = db.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.sender_id == current_user.username, Message.sender_del == False)
		message_thread_recipient = db.session.query(Message).filter(Message.thread_id == request.args.get('thread_id'), Message.recipient_id == current_user.username, Message.recipient_del == False)
		message_thread = message_thread_sender.union(message_thread_recipient).order_by(Message.timestamp.asc())
		##########

		if not message_thread.count():
				abort(404)


		#Custom pagination handler. Helps with older message ajax fetch requests and first /messages/ pull request offset.
		thread_count = len(message_thread.all())
		if thread_count <= 5:
			offset = 0
		else:
			offset = thread_count-5
		message_thread_paginated = message_thread.offset(offset).limit(5)

		if request.args.get('fetch'): #Need to see if database check for existence is needed here / how flask handles error when in production.

			fetch_last_query = db.session.query(Message).filter(Message.url == request.args.get('fetch')).one()
			testq = message_thread_sender.union(message_thread_recipient).order_by(Message.timestamp.asc()).filter(Message.id < fetch_last_query.id) #Replace this union alreay occurs above.
			testq_count = testq.count()
			if testq_count-5 < 0:
				offsetcnt = 0
			else:
				offsetcnt = testq_count-5
			testq = testq.offset(offsetcnt)

			fetched_messages = render_template('fetch_new_message.html', message_thread=testq)
			return {'status': 200, 'fetched_messages': fetched_messages, 'offsetcnt':offsetcnt}
		##########


		#This marks all messages within thread that are in the current_user's unread as read upon thread open if current user is recipient.
		for message in message_thread:
			if current_user.username == message.recipient_id:
				if message.read == False:
					message.read = True
					db.session.commit()
		##########

		#This sets the recipient ID on replies so even if a user is sending themself a thread the recipient ID will be correct. Possibly/probably refactor.
		if current_user.username == message_thread[0].sender_id:
			recip = message_thread[0].recipient_id
		else:
			recip = message_thread[0].sender_id
		##########

		#Notifies socket if messages are all read to sync orange mailbox notification.
		if not db.session.query(Message).filter(Message.recipient_id == current_user.username, Message.read == False).all():
			socketio.emit(str(current_user.websocket_id)+'_notify', {'type':'mailbox', 'notify':'false'}, namespace='/messages')
		##########

		#Notifies socket when the thread is read so the messages page may update read/unread.
		socketio.emit(str(current_user.websocket_id) +'_notify', {'type':'thread', 'notify':'false', 'thread_id':request.args.get('thread_id')}, namespace='/messages')
		##########

		return render_template('read_message_thread.html', message_thread=message_thread_paginated, thread_id=request.args.get('thread_id'),\
								recip=recip, thread_count=thread_count)


	else:
		page = request.args.get('page', 1, type=int)

		unread_messages = db.session.query(Message).filter(Message.recipient_id == current_user.username, Message.recipient_del == False).order_by(Message.timestamp.desc())


		#This sorts each message thread properly according to the datetime of the last recieved message in each thread which is then used in the custom sort_order
		unread_ids = {}

		for message in unread_messages:
			if not unread_ids.get(message.thread_id):
				unread_ids[message.thread_id] = len(unread_ids)+1
		if not unread_ids:
			sort_order = None
		else:
			sort_order = case(value=Message.thread_id, whens=unread_ids).asc()
		##########


		#This fixes message threads viewed on /messages/ so duplicates will not be displayed, using sqlalchemy's '.in_' for query on list items
		thread_list = []
		message_thread_list = []
		for message in unread_messages:
			if message.thread_id not in thread_list:
				thread_list.append(message.thread_id)
				message_thread_list.append(message.url)
		##########


		message_threads = unread_messages.filter(Message.url.in_(message_thread_list)).order_by(sort_order)


		#Determines what is highlighted on the private messages screen for new unread messages and threads. List is passed to messages.html where Jinja2 logic executes.
		unread_threads = unread_messages.filter(Message.read == False).order_by(Message.timestamp.desc()).all()
		if unread_threads:
			unread_threads_list = []
			for message in unread_threads:
				unread_threads_list.append(message.thread_id)
		else:
			unread_threads_list = []
		##########


		message_threads = message_threads.paginate(page, 5, False)

		#This returns rendered threads for insert when the "Load additional threads" button is clicked on /Messages/
		if page > 1:
			paged_threads = render_template('fetch_new_thread.html', messages=message_threads.items, unread_threads_list=unread_threads_list)

			if not unread_messages.filter(Message.url.in_(message_thread_list)).order_by(sort_order).paginate(page+1, 5, False).items:
				fetch_button = 'false'
			else:
				fetch_button = 'true'

			return {'status':200, 'threads':paged_threads, 'fetch_button':fetch_button}
        ##########

		#Determines if the fetch additional threads button is shown on the /messages/ page.
		if len(message_thread_list) > 5:
			fetch_button = 'true'
		else:
			fetch_button = 'false'
		##########

		return render_template('messages.html', messages=message_threads.items, unread_threads_list=unread_threads_list, fetch_button=fetch_button)



@app.route('/messages/socket/', methods=['POST', 'GET']) #Add additional db check here for sender/recip del true and return 404 if so.
@login_required
def message_socket():

	message = db.session.query(Message).filter(Message.url == request.args.get('url')).all()

	if not message:
		abort(404)

	if current_user.username == message[0].recipient_id or current_user.username == message[0].sender_id:
		pass
	else:
		return {'status': 401}


	if current_user.username == message[0].recipient_id and request.args.get('read'):
		message[0].read = True #Maybe change this to ajax request when div is scrolled into view.
		db.session.commit()

		if not db.session.query(Message).filter(Message.recipient_id == current_user.username, Message.read == False, Message.recipient_del == False).all():
			socketio.emit(current_user.websocket_id+'_notify', {'type':'mailbox', 'notify':'false'}, namespace='/messages')


	if request.args.get('read'):
		socketio.emit(current_user.websocket_id+'_notify', {'type':'thread', 'notify':'false', 'thread_id':message[0].thread_id}, namespace='/messages')
		render_message = render_template('fetch_new_message.html', message_thread=message)
		return {'status':200, 'message':render_message}
	else:
		render_thread = render_template('fetch_new_thread.html', messages=message, unread_threads_list=[message[0].thread_id])
		return {'status':200, 'thread':render_thread, 'thread_id':message[0].thread_id}


@app.route('/messages/new/', methods=['POST', 'GET'])
@login_required
def sendmessage():

    if request.method == 'GET':
        return render_template('send_message.html')

    if request.method == 'POST':

        #Data security checks
        if request.json.get('body') == '' or request.json.get('body') == None or len(request.json.get('subject')) > 70:
            return {'status':418}

        #Mitigates messaging attacks by ensuring thread_id has not been modified on the end user computer by checking thread ownership.
        if request.json.get('thread_id'):
            if db.session.query(Message).filter(Message.thread_id == request.json.get('thread_id'), Message.sender_id == current_user.username).all() or \
                db.session.query(Message).filter(Message.thread_id == request.json.get('thread_id'), Message.recipient_id == current_user.username).all():
                    pass
            else:
                return {'status': 418}
		##########


        #Username exists validator
        if not db.session.query(User).filter(User.username == request.json.get('recipient_id').lower()).first():
            return {'error':'No user exists with that username.'}
		##########

        url = randstrurl(type=Message)
        timestamp=datetime.utcnow()

        if request.json.get('thread_id'):
            thread_id = request.json.get('thread_id')
            thread_query = db.session.query(Message).filter(Message.thread_id == thread_id)
            subject = thread_query.order_by(Message.timestamp.desc()).first().subject

        else:
            thread_id = randstrurl(type=Message, pmthread=True)
            subject = request.json.get('subject')


        new_message = Message(sender_id=current_user.username, recipient_id=request.json.get('recipient_id').lower(), subject=subject, body=request.json.get('body'), url=url, \
                    thread_id=thread_id, timestamp=timestamp, sender_del=False, recipient_del=False)
        db.session.add(new_message)
        db.session.commit()
        flash(f'Message sent')
    

        recipient_websocket_id = db.session.query(User).filter(User.username == request.json.get('recipient_id').lower()).one().websocket_id

        socketio.emit(str(recipient_websocket_id)+'_newmsg', {'message_url' : url}, namespace='/messages') #Recipient websocket messages home listener
        socketio.emit(str(current_user.websocket_id)+'_newmsg', {'message_url' : url}, namespace='/messages') #Messages home listener/thread fetch for sender (Maybe not needed)
        socketio.emit(thread_id, {'message_url' : url}, namespace='/messages') #In thread listener  
        
        return {'status': 200}
		



@app.route('/messages/delete/', methods=['POST'])
def message_delete():

	if not current_user.is_authenticated:
		return {'status':401}

	if request.json.get('type') == 'thread':
		thread_messages = db.session.query(Message).filter(Message.thread_id == request.json.get('url')).all()

		for message in thread_messages:
			if message.recipient_id == current_user.username:
				message.recipient_del = True
				db.session.commit()

			if message.sender_id == current_user.username:
				message.sender_del = True
				db.session.commit()

		#Emits thread deletion notification so frontend may update. Also sends total unique threads to determine if fetch additional threads button remains.
		sender_messages = db.session.query(Message).filter(Message.thread_id == message.thread_id, Message.sender_id == current_user.username, Message.sender_del == False)
		recipient_messages = db.session.query(Message).filter(Message.thread_id == message.thread_id, Message.recipient_id == current_user.username, Message.recipient_del == False)
		total_threads = sender_messages.union(recipient_messages).distinct(Message.thread_id).count()

		socketio.emit(str(current_user.websocket_id)+'_notify_deletion', {'type':'thread', 'thread_id':request.json.get('url'), 'total_threads':total_threads}, namespace='/messages')
		##########

		flash('Message thread deleted', 'success')
		

	if request.json.get('type') == 'message':
		message = db.session.query(Message).filter(Message.url == request.json.get('url')).first()

		if message.recipient_id == current_user.username:
			message.recipient_del = True
			db.session.commit()

		if message.sender_id == current_user.username:
			message.sender_del = True
			db.session.commit()

		#Emits thread deletion notification so frontend may update. Also passes total messages in thread so if 0 a redirect is instructed.
		sender_messages = db.session.query(Message).filter(Message.thread_id == message.thread_id, Message.sender_id == current_user.username, Message.sender_del == False)
		recipient_messages = db.session.query(Message).filter(Message.thread_id == message.thread_id, Message.recipient_id == current_user.username, Message.recipient_del == False)
		total_messages = sender_messages.union(recipient_messages).count()

		socketio.emit(str(current_user.websocket_id)+'_notify_deletion', {'type':'message', 'message_url':request.json.get('url'), 'thread_id':message.thread_id, 'total_messages':total_messages}, namespace='/messages')
		##########

		return {'status': 200}
############

@app.route('/result')
def result():
	if request.args.get('q'):

		searched_user = request.args.get('q').lower()
		searched = User.query.msearch(searched_user, fields=['username'], limit=1)
		if not User.query.filter(User.username == searched_user).all():
			flash(f"Check ur spelling and try again", 'danger')



		if searched_user == current_user.username:
			flash(f'This is u bruh :)', 'success')
			
		return render_template('result.html', searched_user=searched_user, searched=searched)
	else:
		flash(f'Please input the username before u click on the search button', 'danger')
		return redirect(url_for('index'))


if __name__ == "__main__":
    socketio.run(app)