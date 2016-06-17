from flask import Flask, render_template, session, request,\
	make_response, redirect, url_for, Response, jsonify, session

#OAuth specific
from ims_lti_py import ToolProvider
from time import time

from functools import wraps

app = Flask(__name__)
from config import *

# ============================================
# Utility Functions
# ============================================

def check_valid_user(f):
   @wraps(f)
   def decorated_function(*args, **kwargs):
       """
       Decorator to check if the user is allowed access to the app.

       If user is allowed, return the decorated function.
       Otherwise, return an error page with corresponding message.
       """
       canvas_user_id = session.get('canvas_user_id')

       if not session.get('lti_logged_in') or not canvas_user_id:
           return render_template('index.html', msg="Login error")

       if not 'course_id' in kwargs.keys():
           return render_template('index.html', msg="Course ID error")

       course_id = int(kwargs.get('course_id'))
       enrollments_url = "%scourses/%s/enrollments" % (API_URL, course_id)
       payload = {
           'user_id': canvas_user_id,
           'type': ['TeacherEnrollment', 'TaEnrollment', 'DesignerEnrollment', 'StudentEnrollment', 'ObserverEnrollment']
       }

       user_enrollments_response = requests.get(
           enrollments_url,
           data=json.dumps(payload),
           headers=json_headers
       )
       user_enrollments = user_enrollments_response.json()
       if not user_enrollments or 'errors' in user_enrollments:
            return render_template('index.html', msg="Error with enrollments request")


       return f(*args, **kwargs)
   return decorated_function

# ============================================
# Web Views / Routes
# ============================================

@app.route("/<int:course_id>")
@check_valid_user
def index(course_id=None):
    """
    Main entry point to web application, call all the things and send the data to the template
    """
    if 'instructor' in session:
        students = fetch_canvas('courses/%s/users?enrollment_type[]=student' % (course_id))
        if 'student' in request.form:
            session['canvas_user_id'] = request.form['student']
        else:
            if session['launch_params']['custom_canvas_user_id'] == session['canvas_user_id']:
                session['canvas_user_id'] = students[0]['id']
        try:
            current_student = [s for s in students if s['id'] == int(session['canvas_user_id'])][0]
        except:
            current_student ={id: 0, name:""}
    else:
        students = []
        current_student = []
    return render_template("index.html", course=course_id, students=students, google=GOOGLE, current_student=current_student)


@app.route("/xml/", methods=['POST', 'GET'])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    print request.url_root
    try:
    	return render_template('test.xml', url=request.url_root)
    except:
    	return render_template('index.html', msg="No XML file")

# ============================================
# LTI Setup & Config
# ============================================

@app.route('/launch', methods = ['POST'])
def lti_tool():
	key = request.form.get('oauth_consumer_key')
	print "1"
	if key:
		secret = oauth_creds.get(key)
		if secret:
			tool_provider = ToolProvider(key, secret, request.form)
		else:
			tool_provider = ToolProvider(None, None, request.form)
			tool_provider.lti_msg = 'Your consumer didn\'t use a recognized key'
			tool_provider.lti_errorlog = 'You did it wrong!'
			return render_template('error.html', 
				message = 'Consumer key wasn\'t recognized',
				params = request.form)
	else:
		return render_template('error.html', message = 'No consumer key')
	print "2"
	if not tool_provider.is_valid_request(request):
		print "3"
		return render_template('error.html', 
			message = 'The OAuth signature was invalid',
			params = request.form)

	if time() - int(tool_provider.oauth_timestamp) > 60*60:
		return render_template('error.html', message = 'Your request is too old.')

	# This does truly check anything, it's just here to remind you  that real
	# tools should be checking the OAuth nonce
	if was_nonce_used_in_last_x_minutes(tool_provider.oauth_nonce, 60):
		return render_template('error.html', message = 'Why are you reusing the nonce?')

	session['launch_params'] = tool_provider.to_params()
	username = tool_provider.username('Dude')
	print "4"
	if tool_provider.is_outcome_service():
		return render_template('index.html', msg="Hi, I'm your LTI!")
	else:
		return redirect(url_for('courses', **request.form))

def was_nonce_used_in_last_x_minutes(nonce, minutes):
    return False


if __name__ == "__main__":
	app.debug = True
	app.secret_key = secret_key

	app.run(host="localhost", port=8080)