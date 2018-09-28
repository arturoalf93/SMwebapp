from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

#afterCF

#for the timestamps I've seen this: default=datetime.utcnow), maybe it's better that datetime.now
'''
https://stackoverflow.com/questions/47622988/sqlalchemy-float8-stored-in-mysql-with-2-decimal-places is this necessary

from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
'''
'''
DO I HAVE TO IMPORT THE MYSQL DIALECT FOR SQLALCHEMY or that is only for the datatypes??
'''

db = SQLAlchemy()

'''Original before scripting
class userstest(db.Model): #this is imported then in main.py, so if the name changes, change the name there as well
	#by default, the table will created using the same name as the class, if we wanted to create a table with a different name (not sure why we would):
	#__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(50), unique = True)
	email = db.Column(db.String(40))
	password = db.Column(db.String(94))
	#In order for the FK to work:
	comments = db.relationship('Comment') #name of the class, not of the table (usually it would be the same.). A column will not be created
	created_date = db.Column(db.DateTime, default = datetime.datetime.now)
'''
class userstest(db.Model):
	id = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	comments = db.relationship('comments')
	username = db.Column(db.String(50), unique = True, autoincrement = False)
	email = db.Column(db.String(40), autoincrement = False)
	password = db.Column(db.String(94), autoincrement = False)
	created_date = db.Column(db.DateTime, autoincrement = False, default = datetime.datetime.now)

#this goes inside userstest
	def __init__(self, username, password, email):
		self.username = username
		self.password = self.__create_password(password)
		self.email = email

	def __create_password(self, password):
		return generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password, password)
'''
Original one, before script
class Comment(db.Model):
	__tablename__ = 'comments'

	id = db.Column(db.Integer, primary_key = True)
	user_id = db.Column(db.Integer, db.ForeignKey('userstest.id')) #FOREIGN KEY. We also have to write the relationship in userstest
	text = db.Column(db.Text()) #Text is just larger than String
	created_date = db.Column(db.DateTime, default = datetime.datetime.now)
'''

class comments(db.Model):
	id = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	user_id = db.Column(db.Integer, db.ForeignKey('userstest.id'), autoincrement = False)
	text = db.Column(db.String(1000), autoincrement = False)
	created_date = db.Column(db.DateTime, autoincrement = False, default = datetime.datetime.now)



class category_names(db.Model):
	category_nameid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	suitemodcat = db.relationship('suitemodcat')
	category_name = db.Column(db.String(45), nullable = False, autoincrement = False)

class current_quarteryear(db.Model):
	quarter = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)

class element_names(db.Model):
	element_nameid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	suitemodcatelem = db.relationship('suitemodcatelem')
	elementname = db.Column(db.String(100), nullable = False, autoincrement = False)

class elementvariants(db.Model):
	variantid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	suitemodcatelem = db.relationship('suitemodcatelem')
	specification = db.Column(db.String(5000), autoincrement = False)
	example_scoring = db.Column(db.String(2000), autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)

class parentvendors(db.Model):
	parent_vendorid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	vendors = db.relationship('vendors')
	parent_name = db.Column(db.String(45), nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)

class personas(db.Model):
	personaid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	personaname = db.Column(db.String(45), nullable = False, autoincrement = False)
	persona_description = db.Column(db.String(1000), autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)

class rfi(db.Model):
	rfi_id = db.Column(db.Integer, nullable = False, autoincrement = True)
	suitemod_id = db.Column(db.Integer, db.ForeignKey('suitemodules.suitemodid'), primary_key = True, nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	invite_date = db.Column(db.DateTime, nullable = False, autoincrement = False, default = datetime.datetime.now)

class rfielements(db.Model):
	vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.vendorid'), primary_key = True, nullable = False, autoincrement = False)
	smce_id = db.Column(db.Integer, db.ForeignKey('suitemodcatelem.smceid'), primary_key = True, nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	round = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)
	self_score = db.Column(db.Integer, autoincrement = False)
	self_description = db.Column(db.String(5000), autoincrement = False)
	attachment_id = db.Column(db.Integer, autoincrement = False)
	sm_score = db.Column(db.Numeric(2,1), autoincrement = False)
	analyst_notes = db.Column(db.String(1000), autoincrement = False)
	user_id = db.Column(db.Integer, db.ForeignKey('userlogin.userid'), autoincrement = False)

class suitemodcat(db.Model):
	suitemod_id = db.Column(db.Integer, db.ForeignKey('suitemodules.suitemodid'), nullable = False, autoincrement = False)
	suitemodcatid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	suitemodcatelem = db.relationship('suitemodcatelem')
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)
	category_name_id = db.Column(db.Integer, db.ForeignKey('category_names.category_nameid'), nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)

class suitemodcatelem(db.Model):
	suitemodcat_id = db.Column(db.Integer, db.ForeignKey('suitemodcat.suitemodcatid'), nullable = False, autoincrement = False)
	smceid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	rfielements = db.relationship('rfielements')
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)
	element_name_id = db.Column(db.Integer, db.ForeignKey('element_names.element_nameid'), nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)
	variant_id = db.Column(db.Integer, db.ForeignKey('elementvariants.variantid'), nullable = False, autoincrement = False)
	classid = db.Column(db.Integer, autoincrement = False)

class suitemodules(db.Model):
	suite_id = db.Column(db.Integer, db.ForeignKey('suites.suiteid'), nullable = False, autoincrement = False)
	suitemodid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	rfi = db.relationship('rfi')
	suitemodcat = db.relationship('suitemodcat')
	vendors_rfi = db.relationship('vendors_rfi')
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)
	suitemod_name = db.Column(db.String(45), nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)

class suites(db.Model):
	suiteid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	suitemodules = db.relationship('suitemodules')
	suite_name = db.Column(db.String(50), nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)

class user_types(db.Model):
	user_typeid = db.Column(db.Integer, nullable = False, autoincrement = True)
	userlogin = db.relationship('userlogin')
	user_type = db.Column(db.String(45), primary_key = True, nullable = False, autoincrement = False)
	privileges = db.Column(db.String(45), autoincrement = False)
	type_description = db.Column(db.String(500), autoincrement = False)

class userlogin(db.Model):
	userid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = False)
	rfielements = db.relationship('rfielements')
	email = db.Column(db.String(80), nullable = False, autoincrement = False)
	user_type_id = db.Column(db.Integer, db.ForeignKey('user_types.user_typeid'), nullable = False, autoincrement = False)
	password = db.Column(db.String(45), nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False)
	active = db.Column(db.Integer, nullable = False, autoincrement = False)

class vendors(db.Model):
	vendorid = db.Column(db.Integer, primary_key = True, nullable = False, autoincrement = True)
	rfielements = db.relationship('rfielements')
	vendors_rfi = db.relationship('vendors_rfi')
	vendor_name = db.Column(db.String(45), nullable = False, autoincrement = False)
	quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	year = db.Column(db.Integer, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, primary_key = True, nullable = False, autoincrement = False, default = datetime.datetime.now)
	active = db.Column(db.Integer, nullable = False, autoincrement = False)
	parent_vendorid = db.Column(db.Integer, db.ForeignKey('parentvendors.parent_vendorid'), autoincrement = False)
	vendor_weight = db.Column(db.Numeric(3,2), autoincrement = False)

class vendors_rfi(db.Model):
	vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.vendorid'), primary_key = True, nullable = False, autoincrement = False)
	suitemod_id = db.Column(db.Integer, db.ForeignKey('suitemodules.suitemodid'), primary_key = True, nullable = False, autoincrement = False)
	first_quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	first_year = db.Column(db.Integer, nullable = False, autoincrement = False)
	update_date = db.Column(db.DateTime, nullable = False, autoincrement = False, default = datetime.datetime.now)
	participating_this_quarter = db.Column(db.Integer, nullable = False, autoincrement = False)
	current_round = db.Column(db.Integer, autoincrement = False)

