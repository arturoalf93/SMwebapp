from flask import Flask
from flask import render_template
from flask import request
#from flask_wtf import CsrfProtect #this is what the video said, but it gives a warning, the one one line below works without warnings
from flask_wtf import CSRFProtect
import forms
from flask import make_response #for the cookie
from flask import session

from flask import url_for
from flask import redirect

from flask import flash

from flask import g #to allow global variables. They will be alive until the end of after_request, i.e. return response.
#It will be used in only one petition. Two clients cannot share the same global variable.

from config import DevelopmentConfig

from models import db
from models import userstest #name of the MODEL, not table to import
#from models import Comment in CF
from models import comments

from helper import date_format

from flask_mail import Mail
from flask_mail import Message

import threading  #to send the emails in the background so the app is faster
from flask import copy_current_request_context
#after CF
from models import vendors, rfielements, suitemodcatelem, vendors_rfi, suitemodules, suitemodcat, category_names

#####Just for creating raw MySQL queries########
from sqlalchemy import create_engine
eng = create_engine(DevelopmentConfig.SQLALCHEMY_DATABASE_URI)
################################################

import sys
import urllib.parse #to encode urls
import pandas as pd




app = Flask(__name__)
app.config.from_object(DevelopmentConfig) #here is where we decide if Development or Production.
#app.jinja_env.globals.update( urllib.parse.quote = urllib_parse_quote )
#app.jinja_env.globals.update['urllib.parse.quote'] = urllib.parse.quote
#app.jinja_env.globals.update(__builtins__.__dict__)

#before using config:
#app.secret_key = 'my_secret_key' #though it is a good practice to use os.get() to get the secret key, and not write it in the code

#before using config:
#csrf = CsrfProtect(app)

#after config
#csrf = CsrfProtect() #now we do this at the end, in if __name__...
#this is what the video said, but it gives a warning, the one one line below works without warnings
#csrf = CSRFProtect() THIS WASN'T WORKING
csrf = CSRFProtect(app) #from https://flask-wtf.readthedocs.io/en/stable/csrf.html
mail = Mail()

def send_email(user_email, username): #to know where to send it and write the username in the email
	msg = Message('Thank you for signing up!', #title of the email.
		  sender = app.config['MAIL_USERNAME'], 
		  recipients = [user_email])
	msg.html = render_template('email.html', username = username)
	mail.send(msg) #here we actually send the message

@app.errorhandler(404)
def page_not_found(e): #anything works, not only an 'e'
	return render_template('404.html'), 404 #flask doesn't send the error number, we have to do it.


@app.before_request #we use this to validate , like if the user has permission to access that url, or even if we need a visit counter to that url, 
def before_request():
	if 'username' not in session:
		print (request.endpoint) #this gives you the last part of the url
		print ('User needs to log in!')

	#validate the url...validate if the user is authenticated, let's imagine we want to make 'comment' only accessible to authenticated users
	if 'username' not in session and request.endpoint in ['comment']:
		return redirect(url_for('login'))
	elif 'username' in session and request.endpoint in ['login', 'create']: #why an authenticated user would go to login or create, let's send him/her to index
		return redirect(url_for('index')) #the function index, not the route.

	g.test = 'test' #here we create the global variables. ?I guess we could pull all of one vendor's data here??


@app.route('/')
def index():

	'''
	#we are reading cookies here
	#custome_cookie = request.cookies.get('custome_cookie') this would receive the custome_cookie we created and sent ('Eduardo')
	custome_cookie = request.cookies.get('custome_cookies', 'Undefined') #this does: if you don't find custome_cookie within custome_cookies, it returns undefined
	print (custome_cookie)
	'''

	if 'username' in session: #session is our sessions dictionary
		username = session['username']
	title = "Index"
	return render_template('index.html', title = title)



@app.route('/logout') #here we destroy the cookies
def logout():
	if 'username' in session:
		session.pop('username') #destroy cookie
	return redirect(url_for('login')) # to redirect, using url_for we type the function name, not the path, so just 'login', no /asddad/adad/login

@app.route('/login', methods = ['GET', 'POST'])
def login():
	login_form = forms.LoginForm(request.form)
	if request.method == 'POST' and login_form.validate():
		username = login_form.username.data
		password = login_form.password.data

		user = userstest.query.filter_by(username = username).first() #select * from users where username = username limit 1. It returns an object with the information of the user. If not found, it will return a None
		if user is not None and user.verify_password(password):
			success_message = 'Welcome {}'.format(username)
			flash(success_message)
			session['username'] = username
			session['user_id'] = user.id
			return redirect( url_for('index') )
		else:
			error_message = 'Invalid username or password'
			flash(error_message)

		#after a;dding session['username'] = username a few lines above, isn't this one left over?
		#session['username'] = login_form.username.data #a session variable called username will be created each time whose value is the own username
	return render_template('login.html', form = login_form)

@app.route('/cookie')
def cookie():
	#we are creating cookies here
	response = make_response( render_template('cookie.html'))
	response.set_cookie('custome_cookie', 'Eduardo')
	return response

#by default in flask, only method GET, we have to specify POST
@app.route('/comment', methods = ['GET', 'POST'])
def comment():
	comment_form = forms.CommentForm(request.form)
	
	if request.method == 'POST' and comment_form.validate(): #to validate forms inputs. We also had to add it in _macro.html, in the list {{field.errors}}
		'''print(comment_form.username.data)
		print(comment_form.email.data)
		print(comment_form.comment.data)
	else:
		print ("Error in the form!!")'''


		user_id = session['user_id'] #since we work with cookies, this is the way to get the user_id
		comment = comments(user_id = user_id, 
						  text = comment_form.comment.data)

		print(comment)
		db.session.add(comment)
		db.session.commit()
		success_message = "New comment created"
		flash(success_message)

	title = "Flask Course"
	return render_template('comment.html', title = title, form = comment_form)

@app.route('/create', methods = ['GET', 'POST'])
def create():
	create_form = forms.CreateForm(request.form)
	if request.method == 'POST' and create_form.validate():

		user = userstest(create_form.username.data,
						 create_form.password.data,
						 create_form.email.data)

		db.session.add(user) #this needs an objects heredated from model, like user
		db.session.commit() #here we insert it in the database
		#SQLAlchemy is clever enough to know hwo to open and close connections, so we don't have to worry about that if we wrtie those two lines.


		@copy_current_request_context #this is like the bridge to send the email in the background..
		def send_message(email,username):
			send_email(email, username)
		sender = threading.Thread(name='mail_sender', 
								  target = send_message,
								  args = (user.email, user.username)) #arguments of the function that sends the email.

		sender.start()

		success_message = 'User registered in the database'
		flash(success_message)

	return render_template('create.html', form = create_form)

@app.route('/reviews/', methods=['GET'])
@app.route('/reviews/<int:page>', methods = ['GET']) #we have to write it twice to make pages
def reviews(page = 1): # =1 is only the default value, so /reviews/ and /reviews/1 is the same
	per_page = 1000
	comment_list = comments.query.join(userstest).add_columns(
					userstest.username,  #the model, not the table
					comments.text,
					comments.created_date).paginate(page,per_page,True) #(page, rows per page, if True=404, if False: empty)
	return render_template('reviews.html', comments = comment_list, date_format = date_format) #we send the function as a parameter


@app.after_request
def after_request(response):
	return response #always return response


@app.route('/rfi/', methods=['GET'])
@app.route('/rfi/<vendor_name>', methods=['GET'], defaults={ 'module_name' : None})
@app.route('/rfi/<vendor_name>/<module_name>', methods=['GET', 'POST'])
def rfi(vendor_name, module_name):

	vendorid = vendors.query.filter_by(vendor_name = vendor_name).add_columns(vendors.vendorid).first()[1]
	if module_name is None:
		title = vendor_name
		
		'''
		This commented block pulled every module a vendor had participated looking at rfielements, but it's better doing it through the table vendors_rfi
		smce_ids_list_raw = rfielements.query.filter_by(vendor_id = vendorid).add_columns(rfielements.smce_id).all()
		smce_ids_list = set()
		for item in smce_ids_list_raw:
			smce_ids_list.add(item[1])
		module_ids_list_raw = suitemodcatelem.query.filter(suitemodcatelem.smceid.in_(smce_ids_list)).add_columns(suitemodcatelem.module_id).all()

		module_ids_list = set()
		for item in module_ids_list_raw:
			module_ids_list.add(item[1])
		module_ids_list = sorted(module_ids_list)
		print(module_ids_list)

		module_names_raw = modules.query.filter(modules.moduleid.in_(module_ids_list)).add_columns(modules.module_name).all()
		module_names = []
		for item in module_names_raw:
			module_names.append(item[1])
		print(module_names)
		'''
		suitemod_ids_raw = vendors_rfi.query.filter_by(vendor_id = vendorid).add_columns(vendors_rfi.suitemod_id).all()
		print('suitemod_ids_raw',suitemod_ids_raw)

		module_names_list = []
		for item in suitemod_ids_raw: module_names_list.append(suitemodules.query.filter_by(suitemodid = item[1]).add_columns(suitemodules.suitemod_name).first()[1])

		return render_template('rfi:vendor.html', title = title, vendor_name = vendor_name, module_names = module_names_list, urllib_parse_quote = urllib.parse.quote)
	
	else:
		title = vendor_name + ' - ' + module_name

		suitemodid = suitemodules.query.filter_by(suitemod_name = module_name).add_columns(suitemodules.suitemodid).first()[1]
		print('suitemodid', suitemodid)
		suitemodcat_list_raw = suitemodcat.query.filter_by(suitemod_id = suitemodid).add_columns(suitemodcat.suitemodcatid, suitemodcat.category_name_id).all()
		suitemodcat_list = []
		category_name_ids_list = [] #same lenght as suitemodcat_list
		for item in suitemodcat_list_raw:
			suitemodcat_list.append(item[1])
			category_name_ids_list.append(item[2])
		print('suitemodcat_list', suitemodcat_list)
		ids_list_raw = []
		for item in suitemodcat_list:
			ids_list_raw.append(suitemodcatelem.query.filter_by(suitemodcat_id = item).add_columns(suitemodcatelem.suitemodcat_id, suitemodcatelem.smceid, suitemodcatelem.element_name_id, suitemodcatelem.variant_id).all())
		ids_list = [] #[suitemodcatid, [scmeid, elementnameid, variantid]]
		smce_ids_list = []
		for item in suitemodcat_list: ids_list.append([item, []])

		for item1 in ids_list_raw:
			for item2 in item1:
				index = suitemodcat_list.index(item2[1])
				ids_list[index][1].append([item2[2],item2[3],item2[4]])
				smce_ids_list.append(item2[2])

		print('ids_list', ids_list)
		print('smce_ids_list', smce_ids_list)

		names_list = []
		for item in category_name_ids_list:
			names_list.append(category_names.query.filter_by(category_nameid = item).add_columns(category_names.category_name).first()[1])

		print('names_list', names_list)


		#TRYING WITHOUT PANDAS


		'''rfielements_info:
		0 vendor_id
		1 smce_id
		2 quarter
		3 year
		4 round
		5 self_score
		6 self_description
		7 attachment_id
		8 sm_score
		9 analyst_notes
		'''
		rfielements_info_raw = rfielements.query.filter_by(vendor_id = vendorid).filter(rfielements.smce_id.in_(smce_ids_list)).add_columns(rfielements.vendor_id, rfielements.smce_id, rfielements.quarter, rfielements.year, rfielements.round, rfielements.self_score, rfielements.self_description, rfielements.attachment_id, rfielements.sm_score, rfielements.analyst_notes).all()

		rfielements_info=[]
		quarters_header = set()

		for item in rfielements_info_raw:
			rfielements_info.append([item[1], item[2], item[3], item[4], item[5], item[6], item[7], item[8], item[9], item[10]])

		for item in rfielements_info:
			quarters_header.add((item[3], item[2], item[4]))

		quarters_header = sorted(quarters_header) #now it is a list, not a set anymore.


		columns_perquarter = [ [] for _ in range(len(quarters_header))] #creating a list of dimension = number of quarters
		columns_header = set()
		for row in rfielements_info:
			aux_tuple = (row[3], row[2], row[4])
			if aux_tuple not in quarters_header:
				sys.exit("Element's (year, quarter, round) is not in quarters_header")
			else:
				index = quarters_header.index(aux_tuple)
				for i in range(5,10):
					if row[i] is not None and i not in columns_perquarter[index]:
						columns_perquarter[index].append(i)
						columns_header.add((aux_tuple,i))

		for i in range(len(quarters_header)):
			quarters_header[i] = [quarters_header[i], None]

		for quarter in columns_perquarter:
			quarter = sorted(quarter)

		for item1, item2 in zip(quarters_header, columns_perquarter):
			item1[1] = 	item2

		columns_header = sorted(columns_header)
		
		#check everything is alright
		if(sum(len(x) for x in columns_perquarter) != len(columns_header)):
			sys.exit('columns_perquarter lenght != columns_header lenght')

		del columns_perquarter #we moved it to quarters_header, we don't need it anymore.

		rfielements_info_show = [ [None for _ in range(len(columns_header))] for _ in range(len(smce_ids_list)) ]
		#print('rfielements_info', rfielements_info )
		for row in rfielements_info:
			index1 = smce_ids_list.index(row[1])
			for j in range(5,10):
				if row[j] is not None:
					index2 = columns_header.index(((row[3], row[2], row[4]),j))
					rfielements_info_show[index1][index2] = row[j]
		#print('rfielements_info_show', rfielements_info_show )

		print('quarters_header', quarters_header)
		print('columns_header', columns_header)

		return render_template('rfi:vendor:module.html', title = title, vendor_name = vendor_name, module_name = module_name, urllib_parse_quote = urllib.parse.quote, rfielements_info_show = rfielements_info_show, quarters_header = quarters_header, columns_header = columns_header)
		
		#TRYING WITH PANDAS

		rfielements_info_raw = rfielements.query.filter_by(vendor_id = vendorid).filter(rfielements.smce_id.in_(smce_ids_list)).add_columns( rfielements.smce_id, rfielements.quarter, rfielements.year, rfielements.round, rfielements.self_score, rfielements.self_description, rfielements.attachment_id, rfielements.sm_score, rfielements.analyst_notes).all()
		df = pd.DataFrame(rfielements_info_raw)
		df = df.drop('rfielements', 1)
		#print('df \n', df.head())
		#print('df \n')
		df_qyr = df.groupby(['year', 'quarter', 'round']).size().reset_index().rename(columns={0:'count'})

		'''
	year  quarter  round  count
0  2017        2      1    106
1  2017        4      1     34
2  2018        1      1     31'''
		
		#print(df_qyr)
		#print(df_qyr.iloc[1])
		test = []
		for index, row in df_qyr.iterrows():
			test.append([row['year'], row['quarter'], row['round']])
		#print('test \n', test)
		#print('type(test)', type(test))

		df_qy = df.groupby(['year', 'quarter']).size().reset_index().rename(columns={0:'count'})
		#print(df_qy)
		#print(pd.pivot_table(df, index=['year', 'quarter', 'round', 'smce_id'], values = ['self_score']))

		#df_qyr_self_score = df.groupby(['year', 'quarter', 'round', 'self_score']).size().reset_index().rename(columns={0:'count'})
		#print(df_qyr_self_score)


		#return render_template('rfi:vendor:module.html', title = title, vendor_name = vendor_name, module_name = module_name, urllib_parse_quote = urllib.parse.quote, rfielements_info_show = rfielements_info_show, quarters_header = quarters_header, columns_header = columns_header)

db.init_app(app) #this was supposed to be inside if __name__ but it didn't work: https://stackoverflow.com/questions/30764073/sqlalchemy-extension-isnt-registered-when-running-app-with-gunicorn
mail.init_app(app) #same as db.init_app

if __name__ == '__main__':
	#before config:
	#app.run(debug=True)

	csrf.init_app(app) #this one after config
	#db.init_app(app)
	#mail.init_app(app)

	with app.app_context():
		db.create_all() #this will create every table that IS NOT created already

	app.run()





