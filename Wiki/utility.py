import hashlib
import re



#TO BE MOVED TO UTILITY.PY
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def validate_username(username):
	if USER_RE.match(username):
		return True
	else:
		return False

def validate_password(password):
	if PASS_RE.match(password):
		return True
	else:
		return False

def validate_email(email):
	if EMAIL_RE.match(email):
		return True
	else:
		return False
########################

#To be moved to utility.py
SECRET = 'a;lsdj093533FDAJKNB91ASDSG3551'
#pass in a val to be secured. val is hashed with secret string and the hash is returned
def make_secure_val(val):
	h = hashlib.sha256(val + SECRET).hexdigest()
	return h

#pass in a val to be checked against a hash. If the val + secret hash matches the hash
#passed in return True, else return False
def check_secure_val(val, h):
	if hashlib.sha256(val + SECRET).hexdigest() == h:
		return True
	else:
		return False