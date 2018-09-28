from wtforms import Form
from wtforms import StringField, TextField, PasswordField, TextAreaField, IntegerField, DecimalField, SubmitField, FileField, SelectField
from wtforms.fields.html5 import EmailField
from wtforms import HiddenField #for HoneyPot
from wtforms import validators
from models import userstest #name of the model, not table
#from models import Comment #model, not table. #In CF
from models import comments


def length_honeypot(form, field): #custom function, will receive the form and the field, and we must validate that it's empty
	if len(field.data) > 0:
		raise validators.ValidationError('The field must be empty')

#working with forms is working with objects, so we create class
class CommentForm(Form):
	'''username = StringField('username', 
		[
		validators.Required(message = 'Username is a required field'), validators.length(min=4, max=25, message = 'Insert a valid username')
		])
	email = EmailField( 'Email Address',
		[
			validators.Required( message = 'Email address is a required field'),
			validators.Email(message = 'Inster a valid email')
		])''' 
	comment = TextAreaField('Comment below')
	honeypot = HiddenField('', [ length_honeypot ])

class LoginForm(Form):
	username = StringField('Username',
		[
		 validators.Required (message = 'Username is a required field!'),
		 validators.length(min=4, max=25, message= 'Insert a valid username!'),
		])
	password = PasswordField('Password', 
		[
		 validators.Required(message = 'Password is a requirede field!')
		])
	honeypot = HiddenField('', [ length_honeypot ])

class CreateForm(Form):
	username = TextField('Username', 
		[
		validators.Required(message = 'Username is a required field!'),
		validators.length(min=4, max=50, message='Insert a valid username') 
		])
	email = EmailField('Correo electronico',
		[	
		validators.Required(message = 'Email is a required field!'),
		validators.Email(message='Insert a valid email'),
		validators.length(min=4, max=50, message='Insert a valid email')
		])
	password = PasswordField('Password', 
		[
		validators.Required(message='Password is a required field')
		])

	def validate_username(form,field): #we overrride. We want to validate the user is not already in the database
		username = field.data
		user = userstest.query.filter_by(username = username).first()
		if user is not None:
			raise validators.ValidationError('Username is already registered')

class ElementForm(Form):
	ss = SelectField('', choices=[(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)], coerce = int) #find out how choices work
	sd = StringField('sd') #find out how to set maxlenght
	at = FileField('at')
	sm = DecimalField('sm', places = 1)
	an = StringField('an')










