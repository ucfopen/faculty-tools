from flask import Flask, render_template, session, request, redirect, url_for

# OAuth specific
from ims_lti_py import ToolProvider
from time import time
from pycanvas import Canvas
from pycanvas.exceptions import CanvasException
from functools import wraps
import requests
import json
import config

app = Flask(__name__)

json_headers = {'Authorization': 'Bearer ' + config.API_KEY, 'Content-type': 'application/json'}
canvas = Canvas(config.API_URL, config.API_KEY)

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
        canvas_user_id = request.form.get('custom_canvas_user_id')
        if not request.form.get('custom_canvas_user_id') or not canvas_user_id:
            return render_template(
                'error.html',
                msg='Not allowed!'
            )

        course_id = int(request.form.get('custom_canvas_course_id'))
        if not request.form.get('custom_canvas_course_id') or not course_id:
            return render_template(
                'error.html',
                msg='No course_id provided.'
            )

        # make sure that they are enrolled in this course
        course = canvas.get_course(course_id)
        user_enrollments = course.get_enrollments()
        enrolled = False

        for enrollment in user_enrollments:
            if enrollment.user_id == int(canvas_user_id):
                enrolled = True

        roles = request.form['roles']
        if "Administrator" in roles:
            session['admin'] = True
            session['instructor'] = True
        if "Instructor" in roles:
            session['instructor'] = True

        if 'instructor' not in session:
            return render_template(
                'error.html',
                msg='You are not enrolled in this course as a Teacher, TA, or Designer.'
            )

        if enrolled is False and 'admin' not in session:
            return render_template(
                'error.html',
                msg='You are not enrolled in this course as a Teacher, TA, or Designer.'
            )

        return f(*args, **kwargs)
    return decorated_function


# ============================================
# Web Views / Routes
# ============================================
@app.route("/")
# @check_valid_user
def index():
    """
    Main entry point to web application, call all the things and send the data to the template
    """

    # Get data from the higher level account
    # account = canvas.get_account(config.UCF_ID)
    # for dev
    account = canvas.get_account(1)
    global_ltis = account.get_external_tools()
    course = canvas.get_course(session['course_id'])
    course_ltis = course.get_external_tools()
    lti_requests = []
    lti_list = []

    for lti in course_ltis:
        lti_requests.append(lti)
    for lti in global_ltis:
        lti_requests.append(lti)

    # load our white list
    json_data = json.loads(open('whitelist.json').read())

    # user = session.get('canvas_user_id')

    for lti in lti_requests:
        try:
            # check if the LTI is in the whitelist
            for data in json_data:
                if lti.name in data['name']:
                    lti_list.append({
                        "name": lti.name,
                        "id": lti.id,
                        "sessionless_launch_url": lti.get_sessionless_launch_url(),
                        "desc": data['desc'],
                        "heading": data['subheading'],
                        "screenshot": data['screenshot'],
                        "logo": data['logo'],
                        "filter_by": data['filter_by']
                    })

        except CanvasException:
            # this lti threw an exception when talking to Canvas
            pass

    return render_template(
        "mockup1.html",
        ltis=lti_list,
        course=session['course_id']
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


@app.route("/mockup/", methods=['POST', 'GET'])
def mockup():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    return render_template('mockup1.html')

# OAuth login


@app.route('/oauthlogin', methods=['POST', 'GET'])
# @check_valid_user
def oauth_login():
    # print "oauthlogin session", session, "oauth login session"
    # print "oauthlogin request", request.args, "ouathlogin request"
    # print session.get('canvas_user_id')

    code = request.args.get('code')
    payload = {
        'grant_type': 'authorization_code',
        'client_id': config.oauth2_id,
        'redirect_uri': config.oauth2_uri,
        'client_secret': config.oauth2_key,
        'code': code
    }
    r = requests.post(config.BASE_URL+'login/oauth2/token', data=payload)
    if 'access_token' in r.json():
        config.API_KEY = r.json()['access_token']
        # go to index
        # return render_template("mockup1.html")
        return redirect(url_for('index'))
    else:
        # authentication error
        msg = "Authentication error, please refresh and try again."
        return render_template("error.html", msg=msg)


@app.route('/auth', methods=['POST', 'GET'])
@check_valid_user
def auth():
    session.clear()
    session['course_id'] = request.form.get('custom_canvas_course_id')
    session['canvas_user_id'] = request.form.get('custom_canvas_user_id')

    # if they aren't in our DB/their token is expired or invalid
    return redirect(config.BASE_URL+'login/oauth2/auth?client_id='+config.oauth2_id +
                    '&response_type=code&redirect_uri='+config.oauth2_uri)


# ============================================
# LTI Setup & Config
# ============================================

@app.route('/launch', methods=['POST'])
def lti_tool():
    return "hi"

if __name__ == "__main__":
    app.debug = True
    app.secret_key = config.secret_key
    app.run(host="0.0.0.0", port=config.port)
