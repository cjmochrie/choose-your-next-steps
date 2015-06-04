import string
import webapp2
import jinja2
import os
import logging
import json
import utility
import datetime
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)


#TEMPLATES
SIGNUP_TEMPLATE = 'signup_template.html'
LOGIN_TEMPLATE = 'login_template.html'
MAIN_PAGE_TEMPLATE = 'main_page_template.html'
WIKI_TEMPLATE = 'wiki_template.html'
EDIT_WIKI_TEMPLATE = 'edit_wiki_template.html'
WIKI_HISTORY_TEMPLATE = 'wiki_history_template.html'

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

#User class
#Features to add: keep track of pages modified
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty(required = False)

	#Steve's class functions modified
	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = utility.make_secure_val(pw)
		return User(name = name, pw_hash = pw_hash, email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and utility.check_secure_val(pw, u.pw_hash):
			return u

#Steve's Handler class
class Handler(webapp2.RequestHandler):
	user_logged_in = False

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	#takes filename and parameters, creates file with template
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	#set a cookie of the format: 'name = val,val_hash'
	def set_secure_cookie(self, name, val):
		val_hash = utility.make_secure_val(val)
		cookie_unicode = '%s=%s|%s; Path=/' % (name, val, val_hash)
		cookie_string = str(cookie_unicode)
		self.response.headers.add_header('Set-Cookie', cookie_string)

	#return the value of a cookie of format 'name = val,val_hash' only if it matches the hash
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		if cookie_val:
			val = cookie_val.split('|')[0]
			val_hash = cookie_val.split('|')[1]

			if utility.check_secure_val(val, val_hash):
				return val

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		username = self.read_secure_cookie('name')

		if username and User.by_name(username):
			self.user_logged_in = True

		self.format =''
		if self.request.url.endswith('.json'):
			self.format = 'json'
		else:
			self.format = 'html'

		#NEED CODE FOR .JSON HERE
class Signup(Handler):
	def get(self):
		self.render(SIGNUP_TEMPLATE)

	def post(self):
		username, password, verify, email = '', '', '', ''
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		if username: valid_username = utility.validate_username(username)
		else: valid_username = False

		if password: valid_password = utility.validate_password(password)
		else: valid_password = False

		if email: valid_email = utility.validate_email(email)
		else: valid_email = True

		passwords_match = True if password == verify else False

		if User.by_name(username): username_not_taken = False
		else: username_not_taken = True

		no_error = valid_username and valid_password and valid_email and passwords_match and username_not_taken

		params = {
			'username': username,
			'email': email,
			'valid_username': valid_username,
			'valid_password': valid_password,
			'valid_email': valid_email,
			'passwords_match': passwords_match,
			'username_not_taken': username_not_taken
		}

		#if anything wrong with user entry re-render the signup page
		if not no_error:
			self.render(SIGNUP_TEMPLATE, **params)
		else:
			#add user to database
			user = User.register(username, password, email)
			user.put()

			#log the user in
			self.set_secure_cookie('name', user.name)

			self.redirect('/')


class Login(Handler):
	def get(self):
		self.render(LOGIN_TEMPLATE)

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		user = User.login(username, password)

		if user:
			self.set_secure_cookie('name', user.name)
			self.redirect('/')

		else:
			self.render(LOGIN_TEMPLATE, username = username, error_msg = 'Invalid username or password')

class Logout(Handler):
 	def get(self):
 		self.response.headers.add_header('Set-Cookie', 'name=; Path=/')
		self.redirect('/')


class MainPage(Handler):
	def get(self):

		username = 'Guest'

		#check to see if user is logged in
		if self.user_logged_in:
			user = User.by_name(self.read_secure_cookie('name'))
			username = user.name


		wiki_list = Wiki.get_all_wikis()
		self.render(MAIN_PAGE_TEMPLATE, username = username, wiki_list = wiki_list)

class WikiHandler(Handler):
	def get(self, title = ''):
		username = 'Guest'
		content, created, author = '','',''

		#check to see if user is logged in
		if self.user_logged_in:
			user = User.by_name(self.read_secure_cookie('name'))
			username = user.name

		wiki = Wiki.get_wiki_by_title(title)

		if wiki:
			content = wiki.content
			created = wiki.created
			author = wiki.last_author
			self.render(WIKI_TEMPLATE, title = title, content = content, created = created, username = username, author = author)
		elif username != 'Guest':
			self.redirect('/_edit/' + title)
		else:
			self.redirect('/login')


class EditHandler(Handler):
	def get(self, title = ''):

		username = 'Guest'
		content, created, author = '','',''

		#check to see if user is logged in
		if self.user_logged_in:
			user = User.by_name(self.read_secure_cookie('name'))
			username = user.name

		wiki = Wiki.get_wiki_by_title(title)

		if wiki:
			content = wiki.content
			created = wiki.created
			author = wiki.last_author

		if self.user_logged_in:
			self.render(EDIT_WIKI_TEMPLATE, title = title, content = content, username = username)
		else:
			self.redirect('/login')

	def post(self, title = ''):

		title, content = '', ''
		title = self.request.get('title')
		content = self.request.get('content')
		author = User.by_name(self.read_secure_cookie('name')).name

		wiki = Wiki.get_wiki_by_title(title)
		if wiki:
			wiki.add_revision(content = content, author = author)

		else:
			wiki = Wiki(title = title, content = content, last_author = author)
			wiki.put()

		#time.sleep(1)
		self.redirect('/' + title)

class HistoryHandler(Handler):
	def get(self, title = ''):
		username = 'Guest'
		content, created, author = '','',''

		#check to see if user is logged in
		if self.user_logged_in:
			user = User.by_name(self.read_secure_cookie('name'))
			username = user.name

		wiki = Wiki.get_wiki_by_title(title)
		revisions = wiki.get_all_revisions()
		if revisions:
			self.render(WIKI_HISTORY_TEMPLATE, revisions = revisions, title = title, username = username)
		else:
			self.redirect('/'+title)

class Wiki(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	last_author = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now = True)
	has_revisions = db.BooleanProperty(default = False)

	# @classmethod
	# def get_author_by_title(cls, title):
	# 	u = cls.all().filter('title =', title).get()
	# 	if u:
	# 		return u.last_author

	@classmethod
	def get_wiki_by_title(cls, title):
		wiki = cls.all().filter('title =', title).get()
		if wiki:
			return wiki

	@classmethod
	def get_all_wikis(cls):
		logging.error("getting all wikis")
		wikis = db.GqlQuery('SELECT * ' 'FROM Wiki' ' ORDER BY created DESC')
		wikis = list(wikis)
		wiki_list = []
		for wiki in wikis:
			wiki_list.append(wiki.title)

		logging.error(wiki_list)
		return wiki_list

	def add_revision(self, content, author):
		self.last_author = author
		WikiRevision(wiki = self, content = self.content, author = self.last_author, created = self.created).put()
		self.content = content
		self.last_author = author
		self.has_revisions = True
		self.put()

	def get_all_revisions(self):
		revisions = [{'content' : self.content, 'author': self.last_author, 'created': self. created}]

		for revision in self.wiki_revisions:
			revisions.append({'content' : revision.content, 'author': revision.author, 'created' : revision.created})
		return sorted(revisions, key = lambda k: k['created'], reverse = True)



class WikiRevision(db.Model):
	wiki = db.ReferenceProperty(Wiki, collection_name='wiki_revisions')
	content = db.TextProperty(required = True)
	author = db.StringProperty(required = True)
	created = db.DateTimeProperty(required = True)




app = webapp2.WSGIApplication([('/', MainPage), ('/signup', Signup), ('/logout', Logout), ('/login', Login), (r'/(\w+)(?:.json)?', WikiHandler), ('/_edit' + r'/(\w+)(?:.json)?', EditHandler), ('/_history' + r'/(\w+)(?:.json)?', HistoryHandler)], debug=True)