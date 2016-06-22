from flask import Flask, render_template, session, request, redirect, url_for

#OAuth specific
from ims_lti_py import ToolProvider
from time import time
from pycanvas import Canvas
from functools import wraps
import requests
import json
app = Flask(__name__)
from config import *

json_headers = {'Authorization': 'Bearer ' + API_KEY, 'Content-type': 'application/json'}
canvas = Canvas(API_URL, API_KEY)

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
        # canvas_user_id = session.get('canvas_user_id')
        # if not session.get('lti_logged_in') or not canvas_user_id:
        #     return render_template(
        #         'error.html',
        #         message='Not allowed!'
        #     )
        # if not 'course_id' in kwargs.keys():
        #     return render_template(
        #         'error.html',
        #         message='No course_id provided.'
        #     )
        # course_id = int(kwargs.get('course_id'))

        # if not session['is_admin']:
        #     enrollments_url = "%scourses/%s/enrollments" % (API_URL, course_id)

        #     payload = {
        #         'user_id': canvas_user_id,
        #         'type': ['TeacherEnrollment', 'TaEnrollment', 'DesignerEnrollment']
        #     }

        #     user_enrollments_response = requests.get(
        #         enrollments_url,
        #         data=json.dumps(payload),
        #         headers=json_headers
        #     )
        #     user_enrollments = user_enrollments_response.json()

        #     if not user_enrollments or 'errors' in user_enrollments:
        #         return render_template(
        #             'error.html',
        #             message='You are not enrolled in this course as a Teacher, TA, or Designer.'
        #         )

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
    course = canvas.get_course(course_id)
    ltis = course.get_external_tools()
    lti_list = []
    user = session.get('canvas_user_id')
    print vars(session)
    print session["roles"], "ROLLS"
    json_data = open("whitelist.json", "r")
    data = json.load(json_data)
    print data
    for lti in ltis:
        # print lti
        print vars(lti)
        
        print "visibility", lti.course_navigation['visibility']
        # if "admin" in session["roles"]
        lti_list.append({"name": lti.name, "id": lti.id, "sessionless_launch_url": lti.get_sessionless_launch_url()})

    return render_template(
        "index.html",
        ltis=lti_list,
        course=course_id
    )


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
@app.route('/launch', methods=['POST'])
def lti_tool():
    """
    Bootstrapper for lti.
    """
    course_id = request.form.get('custom_canvas_course_id')
    canvas_user_id = request.form.get('custom_canvas_user_id')
    roles = request.form['ext_roles']
    session["roles"] = roles

    if not "Administrator" in roles and not "Instructor" in roles:
        return render_template(
            'error.html',
            message='Must be an Administrator or Instructor',
            params=request.form
        )

    session["is_admin"] = "Administrator" in roles

    key = request.form.get('oauth_consumer_key')
    if key:
        secret = oauth_creds.get(key)

        if secret:
            tool_provider = ToolProvider(key, secret, request.form)
        else:
            tool_provider = ToolProvider(None, None, request.form)
            print tool_provider
            tool_provider.lti_msg = 'Your consumer didn\'t use a recognized key'
            tool_provider.lti_errorlog = 'You did it wrong!'
            return render_template(
                'error.html',
                message='Consumer key wasn\'t recognized',
                params=request.form)
    else:
        return render_template('error.html', message='No consumer key')

    if not tool_provider.is_valid_request(request):
        return render_template(
            'error.html',
            message='The OAuth signature was invalid',
            params=request.form)

    if time() - int(tool_provider.oauth_timestamp) > 60*60:
        return render_template('error.html', message='Your request is too old.')

    # This does truly check anything, it's just here to remind you  that real
    # tools should be checking the OAuth nonce
    if was_nonce_used_in_last_x_minutes(tool_provider.oauth_nonce, 60):
        return render_template('error.html', message='Why are you reusing the nonce?')

    session['canvas_user_id'] = canvas_user_id
    session['lti_logged_in'] = True

    session['launch_params'] = tool_provider.to_params()
    # username = tool_provider.username('Dude')

    if tool_provider.is_outcome_service():
        return render_template('assessment.html', username=username)
    else:
        return redirect(url_for('index', course_id=course_id))


def was_nonce_used_in_last_x_minutes(nonce, minutes):
    return False


if __name__ == "__main__":
    app.debug = True
    app.secret_key = secret_key
    app.run(host="127.0.0.1", port=8080)
