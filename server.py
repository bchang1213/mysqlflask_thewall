from flask import Flask, render_template, redirect, request, session, flash
# import the Connector function
from mysqlconnection import MySQLConnector
import re
from flask_bcrypt import Bcrypt
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^([^0-9]*|[^A-Z]*)$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'secret103048580e8w7'

# connect and store the connection in "mysql"
# note that you pass the database name to the function
mysql=MySQLConnector(app,'fullfriends')

@app.route('/')
def index():
	if 'user_id' in session:
		return redirect('/wall')
	return render_template("index.html")

@app.route("/register", methods = ["POST"])
def register():
	form = request.form
	##########################
	# LIST OF ERRORS TO FLASH#
	##########################
	errors = []

	###########################
	#VALIDATING THE FIRST NAME#
	###########################
	if not len(form['first_name']):
		errors.append("Please enter your first name.")
	elif len(form['first_name']) < 2:
		errors.append("First name must contain at least two characters.")
	elif not form['first_name'].isalpha():
		errors.append("First name must only contain alphabetic letters.")

	##########################
	#VALIDATING THE LAST NAME#
	##########################
	if not len(form['last_name']):
		errors.append("Last name cannot be empty!")
	elif len(form['last_name']) < 2:
		errors.append("Last name must contain at least two characters.")
	elif not form['last_name'].isalpha():
		errors.append("Last name must only contain alphabetic letters.")

	######################
	#VALIDATING THE EMAIL#
	######################
	if not len(form['email']):
		errors.append("Please enter your e-mail address.")
	elif not EMAIL_REGEX.match(form['email']):
		errors.append("Please enter a valid e-mail address.")

	#########################
	#VALIDATING THE PASSWORD#
	#########################
	if  not  len(form['password']):
		errors.append("Please enter a password")
	else:
		if len(form['password']) < 8:
			errors.append("Password must be at least 8 characters.")
		if not any([letter.isupper() for letter in form['password']]):
			errors.append("Password must contain at least one uppercase letter.")
		if not any([letter.isdigit() for letter in form['password']]):
			errors.append("Password must contain at least one number.")
		if not any([letter in "!@#$%^&*()-_=+~`\"'<>,.?/:;\}{][|" for letter in form['password']]):
			errors.append("Password must contain at least one special character.")
		if form['password'] != form['passconf']:
			errors.append('Password and confirmation fields must match.')

	##########################
	#IF THERE WERE ANY ERRORS#
	##########################
	if len(errors) > 0:
		for error in errors:
			flash(error, "error")
	else:
		#If there were no validation errors, but the user is using an
		# e-mail that already exists in the database, then:
		#query_db looks for a variable called :email, which is passed as an argument in the data parameter.
		check_email = mysql.query_db("SELECT email FROM users WHERE email = :email", {'email': form['email']})
		if len(check_email):
			flash("Account at that email address ({}) is already taken".format(form['email']), "error")
			return redirect('/')

		#Hashing the password using bcrypt.
		password = form['password']
		hashed_pw = bcrypt.generate_password_hash(password)

		#A dictionary called "data" contains the values from the HTML form data.
		data = {
			'first_name': request.form['first_name'],
			'last_name':  request.form['last_name'],
			'email': request.form['email'],
			'password': hashed_pw
		}
		#The SQL query that we will pass to the method query_db.
		query = """INSERT INTO users (users.first_name, users.last_name, 
			users.email, users.password, users.created_at, users.updated_at) 
		VALUES (:first_name,:last_name, :email,:password, NOW(), NOW())"""
		#The query is called new_user.
		new_user = mysql.query_db(query, data)
		#If the query is successful, then a flash message is displayed.
		if new_user:
				flash('Registration was successful! Please sign-in to continue.',"success")
				return redirect('/')
		else:
			#otherwise, flash an error.
			flash('something went wrong', 'error')

#The route for what happens when the user uses the login form rather than register.
@app.route('/login', methods = ["POST"])
def login():
	form = request.form
	#If the email in the form doesn't match the regex, or if the length of the password given is less than 8:
	if not EMAIL_REGEX.match(form['email']) or len(form['password']) < 8:
		#flash a warning.
		flash('Please enter valid credentials', "error")
		return redirect('/')

	#storing a variable containing the bcrypt hashed password from the form data password.
	encrypted_password = bcrypt.generate_password_hash(form['password'])
	# We pass the email and password data that is given against
	# a record containing the exact email address within the database.
	data = {"email": form['email'], "password": encrypted_password}
	query = "SELECT * FROM users WHERE email = :email"

	users = mysql.query_db(query,data)

	#If the query is successful,
	if len(users):
		#Then the variable user is given the value of the first data entry of the query.
		user = users[0]
		#if the hashed passwords don't match, then flash a warning.
		if not bcrypt.check_password_hash(user['password'],form['password']):
			flash('Account with those credentials could not be found.', 'error')
			return redirect('/')
		else:
			#Otherwise, store the user id in a session, flash a success message, redirect to the submit page.
			session['user_id'] = user['id']
			flash('Login successful!', 'success')
			return redirect('/wall')
	else:
		flash('Account with those credentials could not be found.','error')

@app.route("/logout")
def logout():
	session.clear()
	return redirect('/')


@app.route("/wall")
def wall():
	#Display the user's information, that comes from the users table.
	if 'user_id' not in session:
		flash("You must be signed in to do that!", "error")
		return redirect('/')
	#Query the database to retrieve the user's information, based on the user_id stored in session, that came
	#from the login route and method.
	users = mysql.query_db('SELECT * FROM users WHERE id = :id', {'id':session['user_id']})
	#Use the first entry from the resulting retrieved data.
	user = users[0]
	if not len(users):
		flash("Something went wrong", 'error')
		return redirect('/')

	#DISPLAY MESSAGE POSTS#
	#Now, retrieve the MESSAGE information from the messages table:
	query = """SELECT messages.id AS messageid, CONCAT(users.first_name, users.last_name) AS user_name, messages.message, DATE_FORMAT(messages.created_at, "%m-%d-%Y") AS created_on 
	FROM users
	JOIN messages ON messages.user_id = users.id
	ORDER BY messages.created_at desc"""
	posted_messages = mysql.query_db(query)

	#DISPLAY COMMENTS
	commentquery = """SELECT CONCAT(users.first_name, users.last_name) AS user_name, comments.message_id, comments.comment, comments.created_at
	FROM users
	JOIN comments ON users.id = comments.user_id
	ORDER BY comments.created_at desc"""
	posted_comments = mysql.query_db(commentquery)
	print posted_comments

	return	render_template("success.html", users = user, wallposts = posted_messages, commentposts = posted_comments)

@app.route("/messages", methods = ["POST"])
def post_message():
	#This query will store the messages into the database on the messages table.
	query = """INSERT INTO messages (messages.user_id, messages.message, messages.created_at, messages.updated_at)
	 VALUES(:user_id, :message, NOW(), NOW() )"""

	data = {
	"user_id":session['user_id'],
	"message": request.form['message']
	}

	posted_message = mysql.query_db(query,data)
#If the query is successful, then a flash message is displayed.
	if posted_message:
		flash('Message posted successfully.',"success")
		return redirect('/wall')
	else:
		#otherwise, flash an error.
		flash('something went wrong', 'error')

@app.route("/comments/<messageid>", methods = ["POST"])
def comments(messageid):
	query = """INSERT INTO comments (comments.message_id, comments.user_id, comments.comment, comments.created_at, comments.updated_at)
	 VALUES(:messageid, :user_id, :comment, NOW(), NOW() )"""
	data ={
	"messageid": messageid,
	"user_id" : session['user_id'],
	"comment": request.form['comment']
	}

	posted_comments = mysql.query_db(query,data)
#If the query is successful, then a flash message is displayed.
	if posted_comments:
		flash('Comment posted successfully.',"success")
		return redirect('/wall')
	else:
		#otherwise, flash an error.
		flash('something went wrong', 'error')

app.run(debug=True)