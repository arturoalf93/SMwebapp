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
from models import vendors, rfielements_providers, rfielements_analysts, suitemodcatelem, vendors_rfi, suitemodules, suitemodcat, category_names, element_names, elementvariants, current_quarteryear, users

#####Just for creating raw MySQL queries########
from sqlalchemy import create_engine
eng = create_engine(DevelopmentConfig.SQLALCHEMY_DATABASE_URI)
################################################

import sys
import urllib.parse #to encode urls
import pandas as pd
pd.set_option('display.expand_frame_repr', False) #just to make the print of pandas wider
from sqlalchemy import desc, func, and_, or_
import json
from helper import previous_quarter_year, next_quarter_year, last_self_score, last_sm_score
import numpy as np

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import BaseView, expose




app = Flask(__name__)
app.config.from_object(DevelopmentConfig) #here is where we decide if Development or Production.

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
	return render_template('comment.html', title = title, comment_form = comment_form)

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
@app.route('/rfi/<vendor_name>/', methods=['GET'], defaults={ 'module_name' : None})
@app.route('/rfi/<vendor_name>/<module_name>/', methods=['GET', 'POST'])
def rfi(vendor_name, module_name):

	vendorid = vendors.query.filter_by(vendor_name = vendor_name).add_columns(vendors.vendorid).first()[1]
	current_quarter = current_quarteryear.query.add_columns(current_quarteryear.quarter).first()[1]
	current_year = current_quarteryear.query.add_columns(current_quarteryear.year).first()[1]
	print('current quarter:', current_quarter, current_year)

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
		suitemod_ids_raw = vendors_rfi.query.filter_by(vendor_id = vendorid).filter_by(quarter = current_quarter).filter_by(year = current_year).add_columns(vendors_rfi.suitemod_id, vendors_rfi.status, vendors_rfi.current_round).all()
		print('suitemod_ids_raw',suitemod_ids_raw)

		module_status_round = []
		for item in suitemod_ids_raw: 
			module_name = suitemodules.query.filter_by(suitemodid = item[1]).order_by(desc(suitemodules.update_date)).add_columns(suitemodules.suitemod_name).first()[1]
			if item[2] == 'N':
				status = 'New'
			elif item[2] == 'R':
				status = 'Refreshing'
			elif item[2] == 'E':
				status = 'Existing'
			elif item[2] == 'Z':
				status = 'Not participaging anymore'
			else:
				sys.exit('Status is neither N, R, E or Z')
			current_round = item[3]
			module_status_round.append([module_name, status, current_round])
		print('module_status_round', module_status_round)


		return render_template('rfi:vendor.html', title = title, vendor_name = vendor_name, module_status_round = module_status_round, urllib_parse_quote = urllib.parse.quote)
	
	else:
		title = vendor_name + ' - ' + module_name
		suitemodid = suitemodules.query.filter_by(suitemod_name = module_name).add_columns(suitemodules.suitemodid).first()[1]
		status = vendors_rfi.query.filter_by(vendor_id = vendorid).filter_by(suitemod_id = suitemodid).filter_by(quarter = current_quarter).filter_by(year = current_year).add_columns(vendors_rfi.status).first()[1]
		current_round = vendors_rfi.query.filter_by(vendor_id = vendorid).filter_by(suitemod_id = suitemodid).filter_by(quarter = current_quarter).filter_by(year = current_year).add_columns(vendors_rfi.current_round).first()[1]
		form = forms.ElementForm(request.form)



		'''if status == 'N' or status == 'R': Not necessary anymore since now current_round is 0, 1 or 2.
			current_round = vendors_rfi.query.filter_by(vendor_id = vendorid).filter_by(suitemod_id = suitemodid).add_columns(vendors_rfi.current_round).first()[1]'''

		print('status', status, '\ncurrent_round', current_round)

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

		print('smce_ids_list', smce_ids_list)

		last_provider_submission = rfielements_providers.query.filter_by(vendor_id = vendorid).filter(rfielements_providers.smce_id.in_(smce_ids_list)).order_by(desc(rfielements_providers.update_date)).add_columns(rfielements_providers.update_date, rfielements_providers.user_id).first()[1:] #[date, user_id]
		print('last_provider_submission', last_provider_submission)

		print('ids_list[0]', ids_list[0])

		#Averages table
		categories_names = []
		for item in category_name_ids_list: categories_names.append(category_names.query.filter_by(category_nameid = item).add_columns(category_names.category_name).first()[1])
		categories_names.append('Average Score')
		categories_ss_averages = []
		total_suitemod_ss_sum = 0
		total_suitemod_ss_len = 0
		for item1 in ids_list:
			category_ss_sum = 0
			category_ss_len = 0
			for item2 in item1[1]:
				try:
					current_ss = last_self_score(vendorid, item2[0], current_quarter, current_year)
					category_ss_sum += current_ss
					category_ss_len += 1
					total_suitemod_ss_sum += current_ss
					total_suitemod_ss_len += 1
				except TypeError: pass
			try: category_ss_average = category_ss_sum/category_ss_len
			except ZeroDivisionError: category_ss_average = '-'
			categories_ss_averages.append(category_ss_average)
		total_suitemod_ss_average = total_suitemod_ss_sum/total_suitemod_ss_len
		categories_ss_averages.append(total_suitemod_ss_average)
		print(categories_ss_averages)


		categories_last_quarter_averages = []
		categories_sm_averages = []
		categories_benchmark_averages = []
		for item in range(0,11):
			categories_last_quarter_averages.append('lq' + str(item))
			categories_sm_averages.append('sm' + str(item))
			categories_benchmark_averages.append('b' + str(item))

		print(categories_last_quarter_averages, categories_sm_averages, categories_benchmark_averages)

		summary_table = []

		for item1, item2, item3, item4, item5 in zip(categories_names, categories_ss_averages, categories_last_quarter_averages, categories_sm_averages, categories_benchmark_averages): summary_table.append([item1, item2, item3, item4, item5])
		print(summary_table)


	

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
		#rfielements_info_raw = rfielements.query.filter_by(vendor_id = vendorid).filter(rfielements.smce_id.in_(smce_ids_list)).add_columns(rfielements.vendor_id, rfielements.smce_id, rfielements.quarter, rfielements.year, rfielements.round, rfielements.self_score, rfielements.self_description, rfielements.attachment_id, rfielements.sm_score, rfielements.analyst_notes).all()
		rfielements_providers_info_raw = rfielements_providers.query.filter_by(vendor_id = vendorid).filter(rfielements_providers.smce_id.in_(smce_ids_list)).add_columns(rfielements_providers.vendor_id, rfielements_providers.smce_id, rfielements_providers.quarter, rfielements_providers.year, rfielements_providers.round, rfielements_providers.self_score, rfielements_providers.self_description, rfielements_providers.attachment_id).all()
		rfielements_analysts_info_raw = rfielements_analysts.query.filter_by(vendor_id = vendorid).filter(rfielements_analysts.smce_id.in_(smce_ids_list)).add_columns(rfielements_analysts.vendor_id, rfielements_analysts.smce_id, rfielements_analysts.quarter, rfielements_analysts.year, rfielements_analysts.round, rfielements_analysts.sm_score, rfielements_analysts.analyst_notes).all()

		#df = pd.DataFrame(rfielements_info_raw)
		df_providers = pd.DataFrame(rfielements_providers_info_raw)
		df_providers = df_providers.where(df_providers.notnull(), None) #if there was a row with only a SD but not a SS: the SS appeared as nan
		
		#df_providers['self_score'].astype(np.int64)

		df_analysts = pd.DataFrame(rfielements_analysts_info_raw)
		df_analysts = df_analysts.where(df_analysts.notnull(), None)
	
		#df['yqr'] = df['year'].astype(str) + '-' + df['quarter'].astype(str) + '-' + df['round'].astype(str)
		df_providers['yqr'] = df_providers['year'].astype(str) + '-' + df_providers['quarter'].astype(str) + '-' + df_providers['round'].astype(str)
		df_analysts['yqr'] = df_analysts['year'].astype(str) + '-' + df_analysts['quarter'].astype(str) + '-' + df_analysts['round'].astype(str)

		#yqdict = dict()
		#for item in df.yqr.unique():
		#	yqdict[item] = df[df.yqr == item].drop(columns=['rfielements', 'vendor_id', 'quarter', 'year', 'round', 'smce_id', 'yqr']).dropna(how='all', axis=1)

		yqdict_providers = dict()
		for item in df_providers.yqr.unique():
			yqdict_providers[item] = df_providers[df_providers.yqr == item].drop(columns=['rfielements_providers', 'vendor_id', 'quarter', 'year', 'round', 'smce_id', 'yqr']).dropna(how='all', axis=1)

		yqdict_analysts = dict()
		for item in df_analysts.yqr.unique():
			yqdict_analysts[item] = df_analysts[df_analysts.yqr == item].drop(columns=['rfielements_analysts', 'vendor_id', 'quarter', 'year', 'round', 'smce_id', 'yqr']).dropna(how='all', axis=1)

		#yqr_headers_dicts = [ {item:yqdict[item].columns.tolist()} for item in sorted(yqdict.keys()) ]
		#print('yqr_headers_dicts', yqr_headers_dicts)

		yqr_headers_providers_dicts = [ {item:yqdict_providers[item].columns.tolist()} for item in sorted(yqdict_providers.keys()) ]
		print('yqr_headers_providers_dicts', yqr_headers_providers_dicts)

		yqr_headers_analysts_dicts = [ {item:yqdict_analysts[item].columns.tolist()} for item in sorted(yqdict_analysts.keys()) ]
		print('yqr_headers_analysts_dicts', yqr_headers_analysts_dicts)

		#merge yqr_headers_providers_dicts and yqr_headers_analysts_dicts into yqr_headers_dicts
		yqr_headers_dicts_unsorted = yqr_headers_providers_dicts
		for item_analysts in yqr_headers_analysts_dicts:
			for item in yqr_headers_dicts_unsorted:
				if list(item_analysts.keys())[0] in item:
					for item2 in item_analysts.get(list(item_analysts.keys())[0]):
						item[list(item_analysts.keys())[0]].append(item2)
					break
				else:
					yqr_headers_dicts_unsorted.append(item_analysts)
					break

		#sort yqr_headers_dict
		keys_list = []
		for item in yqr_headers_dicts_unsorted: keys_list.append(list(item.keys())[0])
		keys_list.sort()

		yqr_headers_dicts = []
		for item1 in keys_list:
			for item2 in yqr_headers_dicts_unsorted:
				if item1 == list(item2.keys())[0]:
					print('yes', item1, item2)
					yqr_headers_dicts.append({item1: item2[item1]})
					break

		print('final yqr_headers_dict: ', yqr_headers_dicts)

		#delete current_year & current_quarter item
		indexes = [] #this will be necessary in case we have to delete two rounds
		for index, dictionary in enumerate(yqr_headers_dicts):
			for key in dictionary:
				if int(key.split('-')[0]) == current_year and int(key.split('-')[1]) == current_quarter:
					indexes.append(index)
		for index in reversed(indexes): #it must be backwards since we are removing elements from the list.
			del yqr_headers_dicts[index]


		yq_headers2 = []
		yqr_headers_len = []
		for item in yqr_headers_dicts:
			yq_headers2.append(list(item.keys()))
			yqr_headers_len.append(len(list(item.values())[0]))
		print('yqr_headers_len', yqr_headers_len)
		for item1, item2 in zip(yq_headers2, yqr_headers_len): item1.append(item2)
		#print('yq_headers2', yq_headers2)



		yq_headers = []
		for item in yq_headers2:
			if [item[0].split('-')[0] + '-' + item[0].split('-')[1]] not in yq_headers: yq_headers.append([item[0].split('-')[0] + '-' + item[0].split('-')[1]])
		for item in yq_headers: item.append(0)
		for item1 in yq_headers2:
			aux = item1[0].split('-')[0] + '-' + item1[0].split('-')[1]
			for item2 in yq_headers:
				if aux == item2[0]: 
					item2[1] += item1[1]
					break
		for item in yq_headers: item[0] = [item[0].split('-')[0], item[0].split('-')[1]]
		#yq_headers will define the fist header.
		print('yq_headers', yq_headers)

		#yqr_headers will define the second header
		yqr_headers2 = []
		yqr_headers_columns = []
		yqr_headers3 = []
		yqr_headers=[]

		for item in yqr_headers_dicts:
			yqr_headers2.append(list(item.keys()))
			yqr_headers_columns.append(list(item.values())[0])

		for item1 in yqr_headers_columns:
			for item2 in range(len(item1)):
				if item1[item2] == 'self_score': item1[item2] = 5
				elif item1[item2] == 'self_description': item1[item2] = 6
				elif item1[item2] == 'attachment_id': item1[item2] = 7
				elif item1[item2] == 'sm_score': item1[item2] = 8
				elif item1[item2] == 'analyst_notes': item1[item2] = 9

		for item1, item2 in zip(yqr_headers2, yqr_headers_columns): yqr_headers3.append(((int(item1[0].split('-')[0]), int(item1[0].split('-')[1]), int(item1[0].split('-')[2])), item2))
		for item1 in yqr_headers3:
			for item2 in item1[1]:
				yqr_headers.append((item1[0], item2))
				
		#print('yqr_headers3', yqr_headers3)
		print('yqr_headers_columns', yqr_headers_columns)
		print('yqr_headers', yqr_headers)

		#for item1 in ids_list:
			#for item2 in item1[1]:
				#print('smceid', item2[0], 'variantid', item2[2] ,elementvariants.query.filter_by(variantid = item2[2]).add_columns(elementvariants.example_scoring).first()[1])

		width = 3 + len(yqr_headers)

		info = [] #[category,[element_name, spec, example scoring, ss_q1y1, sd_q1y1, at_q1y1, sm_q1y1, an_q1y1, ss_q2y1, sd_q2y1, at_q2y1, sm_q2y1, an_q2y1...], smceid, [ss_current_round_1] ]
		for item1 in ids_list:
			cat_name_id = suitemodcat.query.filter_by(suitemodcatid = item1[0]).add_columns(suitemodcat.category_name_id).first()[1]
			cat_name = category_names.query.filter_by(category_nameid = cat_name_id).add_columns(category_names.category_name).first()[1]
			info.append([cat_name, item1[0]])
			for item2 in item1[1]:
				row = []
				elem_name = element_names.query.filter_by(element_nameid = item2[1]).add_columns(element_names.elementname).first()[1]
				row.append([elem_name])
				spec = elementvariants.query.filter_by(variantid = item2[2]).add_columns(elementvariants.specification).first()[1]
				row[0].append(spec)
				es = elementvariants.query.filter_by(variantid = item2[2]).add_columns(elementvariants.example_scoring).first()[1]
				row[0].append(es)
				data = None
				'''for item3 in yqr_headers:
					col = None
					if item3[1] == 5: col = 'self_score'
					elif item3[1] == 6: col = 'self_description'
					elif item3[1] == 7: col = 'attachment_id'
					elif item3[1] == 8: col = 'sm_score'
					elif item3[1] == 9: col = 'analyst_notes'
					try:
						data = df.loc[(df['smce_id'] == item2[0]) & (df['year'] == item3[0][0]) & (df['quarter'] == item3[0][1]) & (df['round'] == item3[0][2]), col].tolist()[0]
					except:
						data = None
					row[0].append(data)'''
				for item3 in yqr_headers:
					col = None
					if item3[1] == 5 or item3[1] == 6 or item3[1] == 7:
						if item3[1] == 5: col = 'self_score' 
						elif item3[1] == 6: col = 'self_description'
						elif item3[1] == 7: col = 'attachment_id'
						try:
							if item3[1] == 5: #do self_score alone because it is an integer, but since it has to pass through pandas, it is converted to float. So now we remove the .0 doing int(). If it was null, it would go to except and get a None
								data = int(df_providers.loc[(df_providers['smce_id'] == item2[0]) & (df_providers['year'] == item3[0][0]) & (df_providers['quarter'] == item3[0][1]) & (df_providers['round'] == item3[0][2]), col].tolist()[0])
							else:
								data = df_providers.loc[(df_providers['smce_id'] == item2[0]) & (df_providers['year'] == item3[0][0]) & (df_providers['quarter'] == item3[0][1]) & (df_providers['round'] == item3[0][2]), col].tolist()[0]
						except:
							data = None
						row[0].append(data)
					elif item3[1] == 8 or item3[1] == 9:
						if item3[1] == 8: col = 'sm_score'
						elif item3[1] == 9: col = 'analyst_notes'
						try:
							if item3[1] == 8 and int(df_analysts.loc[(df_analysts['smce_id'] == item2[0]) & (df_analysts['year'] == item3[0][0]) & (df_analysts['quarter'] == item3[0][1]) & (df_analysts['round'] == item3[0][2]), col].tolist()[0]) == df_analysts.loc[(df_analysts['smce_id'] == item2[0]) & (df_analysts['year'] == item3[0][0]) & (df_analysts['quarter'] == item3[0][1]) & (df_analysts['round'] == item3[0][2]), col].tolist()[0]: #same as with self_score
								data = int(df_analysts.loc[(df_analysts['smce_id'] == item2[0]) & (df_analysts['year'] == item3[0][0]) & (df_analysts['quarter'] == item3[0][1]) & (df_analysts['round'] == item3[0][2]), col].tolist()[0])
							else:
								data = df_analysts.loc[(df_analysts['smce_id'] == item2[0]) & (df_analysts['year'] == item3[0][0]) & (df_analysts['quarter'] == item3[0][1]) & (df_analysts['round'] == item3[0][2]), col].tolist()[0]
						except:
							data = None
						row[0].append(data)
				row.append(item2[0]) #appending smceid

				#append current_rounds or [None, None...]
				'''try:
					current_round_1 = rfielements.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 1).order_by(desc(rfielements.update_date)).add_columns(rfielements.self_score, rfielements.self_description, rfielements.attachment_id, rfielements.sm_score, rfielements.analyst_notes).first()[1:6]
				except:
					current_round_1 = [None, None, None, None, None]
				row.append(current_round_1)
				try:
					current_round_2 = rfielements.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 2).order_by(desc(rfielements.update_date)).add_columns(rfielements.self_score, rfielements.self_description, rfielements.attachment_id, rfielements.sm_score, rfielements.analyst_notes).first()[1:6]
				except:
					current_round_2 = [None, None, None, None, None]
				row.append(current_round_2)'''

				#append current_rounds or [None, None...]
				try: current_round_1_providers = rfielements_providers.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 1).order_by(desc(rfielements_providers.update_date)).add_columns(rfielements_providers.self_score, rfielements_providers.self_description, rfielements_providers.attachment_id).first()[1:4]
				except: current_round_1_providers = [None, None, None]
				try: current_round_1_analysts = rfielements_analysts.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 1).order_by(desc(rfielements_analysts.update_date)).add_columns(rfielements_analysts.sm_score, rfielements_analysts.analyst_notes).first()[1:3]
				except: current_round_1_analysts = [None, None]

				current_round_1 = []
				for item in current_round_1_providers: current_round_1.append(item)
				for item in current_round_1_analysts: current_round_1.append(item)
				row.append(current_round_1)

				'''try:
					current_round_2 = rfielements.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 2).order_by(desc(rfielements.update_date)).add_columns(rfielements.self_score, rfielements.self_description, rfielements.attachment_id, rfielements.sm_score, rfielements.analyst_notes).first()[1:6]
				except:
					current_round_2 = [None, None, None, None, None]
				row.append(current_round_2)'''
				try: current_round_2_providers = rfielements_providers.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 2).order_by(desc(rfielements_providers.update_date)).add_columns(rfielements_providers.self_score, rfielements_providers.self_description, rfielements_providers.attachment_id).first()[1:4]
				except: current_round_2_providers = [None, None, None]
				try: current_round_2_analysts = rfielements_analysts.query.filter_by(vendor_id = vendorid, smce_id = item2[0], quarter = current_quarter, year = current_year, round = 2).order_by(desc(rfielements_analysts.update_date)).add_columns(rfielements_analysts.sm_score, rfielements_analysts.analyst_notes).first()[1:3]
				except: current_round_2_analysts = [None, None]

				current_round_2 = []
				for item in current_round_2_providers: current_round_2.append(item)
				for item in current_round_2_analysts: current_round_2.append(item)	
				row.append(current_round_2)

				#append [Current SS, Current SM]
				try:
					'''row_number_column = func.row_number().over(partition_by=(rfielements_providers.vendor_id, rfielements_providers.smce_id), order_by=(desc(rfielements_providers.year), desc(rfielements_providers.quarter), desc(rfielements_providers.round), desc(rfielements_providers.update_date))).label('row_order')
					current_ss = rfielements_providers.query.with_entities(rfielements_providers.self_score, row_number_column).filter_by(vendor_id = vendorid, smce_id = item2[0]).filter(or_(rfielements_providers.year < current_year, and_(rfielements_providers.year == current_year, rfielements_providers.quarter <= current_quarter))).from_self().filter(row_number_column == 1).first()[0]'''
					current_ss = last_self_score(vendorid, item2[0], current_quarter, current_year)
				except TypeError: current_ss = None
				try: current_sm_score = last_sm_score(vendorid, item2[0], current_quarter, current_year)
				except TypeError: current_ss = None
				row.append([current_ss, current_sm_score])

				row.append(item1[0]) #suitemodcatid, will be row[5] in order to make jinja2 & jquery work.
					
				info.append(row)
		#print('info\n', info)

		modified_smceids = []

		if request.method == 'POST' and "submit_button" in request.form: #When the button 'Submit updates' is pressed
			for item1 in info:
				if len(item1) != 2: #when a category, len of the list will be 2: [category_name, ?category_name_id?]
					change = 0 #flag to update current element

					#Check if there is a change in SS
					if request.form['ss-' + str(current_round) + '-' + str(item1[1])] == "" and item1[1+current_round][0] != None: #if there was a SS but now it's NULL
						new_ss = None
						change = 1
					elif request.form['ss-' + str(current_round) + '-' + str(item1[1])] != "" and item1[1+current_round][0] != int(request.form['ss-' + str(current_round) + '-' + str(item1[1])]): #if the SS has changed from one number to another
						new_ss = int(request.form['ss-' + str(current_round) + '-' + str(item1[1])])
						change = 1
					else: new_ss = item1[1+current_round][0] #just in case there is a change in SD, it's not really a new SS

					#Check if there is a change in SD
					if request.form['sd-' + str(current_round) + '-' + str(item1[1])] == "" and item1[1+current_round][1] != None: #if there was a SD but now it's NULL
						new_sd = None
						change = 1
					elif request.form['sd-' + str(current_round) + '-' + str(item1[1])] != "" and item1[1+current_round][1] != request.form['sd-' + str(current_round) + '-' + str(item1[1])]: #if the SD has changed
						new_sd = request.form['sd-' + str(current_round) + '-' + str(item1[1])]
						change = 1
					else: new_sd = item1[1+current_round][1] #just in case there is a change in SD, it's not really a new S

					if change == 1:
						element_row = rfielements_providers(vendor_id = vendorid, smce_id = item1[1], quarter = current_quarter, year = current_year, round = current_round, self_score = new_ss, self_description = new_sd,  attachment_id = None, user_id = 1)
						db.session.add(element_row)
						modified_smceids.append(item1[1])
			if len(modified_smceids) > 0:
				db.session.commit()
				print('commit done')

			if len(modified_smceids) == 0:
				flash('No updates where received')
			elif len(modified_smceids) == 1:
				flash('Updates saved for ' + str(len(modified_smceids)) + ' element')
			elif len(modified_smceids) > 1:
				flash('Updates saved for ' + str(len(modified_smceids)) + ' elements')

			return redirect(urllib.parse.quote( url_for(request.endpoint) + vendor_name))

		#testing helper
		print("current_quarter_year", current_quarter, current_year)
		print("previous_quarter_year", previous_quarter_year(current_quarter, current_year))
		print("next_quarter_year", next_quarter_year(current_quarter, current_year))


		'''
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

		print('quarters_header', quarters_header)
		print('columns_header', columns_header)
		'''


		return render_template('rfi:vendor:module.html', title = title, vendor_name = vendor_name, module_name = module_name, urllib_parse_quote = urllib.parse.quote, 
		info = info, yq_headers = yq_headers, yqr_headers = yqr_headers, width = width, current_quarter = current_quarter, current_year = current_year,
		status = status, current_round = current_round, form = form, modified_smceids = modified_smceids,
		summary_table = summary_table)
		

db.init_app(app) #this was supposed to be inside if __name__ but it didn't work: https://stackoverflow.com/questions/30764073/sqlalchemy-extension-isnt-registered-when-running-app-with-gunicorn
mail.init_app(app) #same as db.init_app

admin = Admin(app, name='SolutionMap Admin', template_mode='bootstrap3')

class users_view(ModelView):
	can_delete = False
	page_size = 50
	column_list = ['userid', 'email', 'user_type','assigned_vendor_id', 'password', 'update_date', 'active', 'registration_date', 'anonymized', 'private']
	column_sortable_list = ['userid', 'email', 'user_type','assigned_vendor_id', 'password', 'update_date', 'active', 'registration_date', 'anonymized', 'private']
	column_exclude_list = ['password' ]

class vendors_view(ModelView):
	column_list = ['vendorid', 'vendor_name', 'quarter', 'year', 'update_date', 'active', 'parent_vendorid', 'vendor_weight']
	page_size = 50
	column_searchable_list = ['vendor_name']
	column_filters = ['vendor_name', 'quarter', 'year']
	can_view_details = True
	column_editable_list = ['vendor_name', 'quarter', 'year'] #inline editing
	create_modal = True
	edit_modal = True
	form_choices = {
    	'quarter': [
       	 	(1, '1'),
        	(2, '2'),
        	(3, '3'),
        	(4, '4')
    	],
    	'year': [
    		(2017, '2017'), (2018, '2018'), (2019, '2019')
    	]
	}
	can_export = True

class vendors_rfi_view(ModelView):
	column_list = ['vendor_id', 'suitemod_id', 'quarter', 'year', 'status', 'current_round']
	'''form_ajax_refs = {
    'suitemod_id': {
        'fields': ['suitemod_name'],
        'page_size': 10
    }
}'''

class rfielements_providers_view(ModelView):
	column_list = ['vendor_id', 'smce_id', 'quarter', 'year', 'round', 'update_date', 'self_score', 'self_description', 'attachment_id', 'user_id']
	page_size = 100

class current_quarteryear_view(ModelView):
	column_list = ['quarter', 'year']
	can_delete = False
	can_create = False
	edit_modal = True
	column_editable_list = ['quarter', 'year']
	form_choices = {
    	'quarter': [
       	 	(1, '1'),
        	(2, '2'),
        	(3, '3'),
        	(4, '4')
    	],
    	'year': [
    		(2017, '2017'), (2018, '2018'), (2019, '2019')
    	]
	}



#admin.add_view(ModelView(users, db.session, name='Users'))
#admin.add_view(ModelView(vendors, db.session))
#admin.add_view(ModelView(vendors_rfi, db.session))
#admin.add_view(ModelView(rfielements_providers, db.session))
#admin.add_view(ModelView(rfielements_analysts, db.session))

admin.add_view(users_view(users, db.session, name = 'Users'))
admin.add_view(vendors_view(vendors, db.session, name = 'Vendors'))
admin.add_view(vendors_rfi_view(vendors_rfi, db.session, name = 'Vendors - RFI'))
admin.add_view(rfielements_providers_view(rfielements_providers, db.session, name = 'RFIelements - Providers'))
admin.add_view(current_quarteryear_view(current_quarteryear, db.session, name = 'Current QY'))


if __name__ == '__main__':
	#before config:
	#app.run(debug=True)

	csrf.init_app(app) #this one after config
	#db.init_app(app)
	#mail.init_app(app)

	with app.app_context():
		db.create_all() #this will create every table that IS NOT created already

	app.run()





