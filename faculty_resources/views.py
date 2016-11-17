from flask import Flask, render_template, session, request, redirect, url_for, g
from datetime import datetime, timedelta
import sqlite3
# OAuth specific
from pycanvas import Canvas
from pycanvas.exceptions import CanvasException
from functools import wraps
import requests
import json
import config

app = Flask(__name__)


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

        if request.form:
            session.permanent = True
            # 1 hour long session
            app.permanent_session_lifetime = timedelta(minutes=60)
            session['course_id'] = request.form.get('custom_canvas_course_id')
            session['canvas_user_id'] = request.form.get('custom_canvas_user_id')

            roles = request.form['roles']
            if "Administrator" in roles:
                session['admin'] = True
                session['instructor'] = True
            if "Instructor" in roles:
                session['instructor'] = True

        # no session and no request
        if not session:
            if not request.form:
                return render_template(
                    'error.html',
                    msg='Not allowed!'
                )

        # no canvas_user_id
        if not request.form.get('custom_canvas_user_id') and 'canvas_user_id' not in session:
            return render_template(
                'error.html',
                msg='Not allowed!'
            )

        # no course_id
        if not request.form.get('custom_canvas_course_id') and 'course_id' not in session:
            return render_template(
                'error.html',
                msg='No course_id provided.'
            )

        # not permitted
        if 'instructor' not in session:
            return render_template(
                'error.html',
                msg='You are not enrolled in this course as a Teacher or Designer.'
            )

        # make sure that they are enrolled in this course
        canvas = Canvas(config.API_URL, config.API_KEY)
        user = canvas.get_user(session['canvas_user_id'])
        user_enrollments = user.get_enrollments()
        enrolled = False

        for enrollment in user_enrollments:
            if enrollment.course_id == int(session['course_id']):
                if enrollment.type == "TeacherEnrollment":
                    enrolled = True

        if enrolled is False and 'admin' not in session:
            return render_template(
                'error.html',
                msg='You are not enrolled in this course as a Teacher or Designer.'
            )

        return f(*args, **kwargs)
    return decorated_function


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(config.DATABASE)
    return db


def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ============================================
# Web Views / Routes
# ============================================


@app.route("/")
@check_valid_user
def index():
    """
    Main entry point to web application, call all the things and send the data to the template
    """

    # Get data from the higher level account
    # account = canvas.get_account(config.UCF_ID)
    # 1 for dev
    canvas = Canvas(config.API_URL, session['api_key'])
    # account = canvas.get_account(config.UCF_ID)
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
            # log here
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
        session['api_key'] = r.json()['access_token']

        if 'refresh_token' in r.json():
            session['refresh_token'] = r.json()['refresh_token']

        if 'expires_in' in r.json():
            # expires in seconds
            # add the seconds to current time for expiration time
            current_time = datetime.now()
            expires_in = current_time + timedelta(seconds=r.json()['expires_in'])
            session['expires_in'] = expires_in
        try:
            curs = get_db().cursor()
            curs.execute("INSERT INTO main (user_id, refresh_key, expires_in) VALUES (?, ?, ?)",
                         (session['canvas_user_id'],
                          session['refresh_token'],
                          session['expires_in']))
            get_db().commit()
            return redirect(url_for('index'))

        except Exception as e:
            # log error
            print e, "Error from db"
            msg = "Authentication error, please refresh and try again."
            return render_template("error.html", msg=msg)

    msg = "Authentication error, please refresh and try again."
    return render_template("error.html", msg=msg)


@app.route('/auth', methods=['POST', 'GET'])
@check_valid_user
def auth():

    # if they aren't in our DB/their token is expired or invalid
    curs = get_db().cursor()
    try:
        curs.execute("SELECT * FROM main WHERE user_id='%s'" % int(session['canvas_user_id']))
        row = curs.fetchall()
        # get or add
        if row:
            for info in row:
                expiration_date = datetime.strptime(info[3], '%Y-%m-%d %H:%M:%S.%f')
                refresh_token = info[2]
            if datetime.now() > expiration_date or 'api_key' not in session:
                # expired! Use the refresh token
                payload = {
                    'grant_type': 'refresh_token',
                    'client_id': config.oauth2_id,
                    'redirect_uri': config.oauth2_uri,
                    'client_secret': config.oauth2_key,
                    'refresh_token': refresh_token
                }
                r = requests.post(config.BASE_URL+'login/oauth2/token', data=payload)
                if 'access_token' in r.json():
                    session['api_key'] = r.json()['access_token']

                    if 'refresh_token' in r.json():
                        session['refresh_token'] = r.json()['refresh_token']

                    if 'expires_in' in r.json():
                        # expires in seconds
                        # add the seconds to current time for expiration time
                        current_time = datetime.now()
                        expires_in = current_time + timedelta(seconds=r.json()['expires_in'])
                        session['expires_in'] = expires_in
                    try:
                        curs.execute("UPDATE main SET expires_in=? WHERE user_id=?",
                                     (session['expires_in'], session['canvas_user_id']))
                        get_db().commit()

                    except Exception as e:
                        # log error
                        print "exception from udpating db"
                        msg = "Authentication error, please refresh and try again."
                        return render_template("error.html", msg=msg)

                    return redirect(url_for('index'))
            else:
                # good to go!
                # test the api key
                auth_header = {'Authorization': 'Bearer ' + config.API_KEY}
                r = requests.get(config.API_URL + 'users/%s/profile' %
                                 (session['canvas_user_id']), headers=auth_header)
                if r.json():
                    return redirect(url_for('index'))
                else:
                    msg = "Authentication error, please refresh and try again."
                    return render_template("error.html", msg=msg)
        else:
            # not in db, go go oauth!!
            return redirect(config.BASE_URL+'login/oauth2/auth?client_id='+config.oauth2_id +
                            '&response_type=code&redirect_uri='+config.oauth2_uri)
    except Exception as e:
        # log error
        print e, "Error from db"
        # they aren't in the db, so send em to the oauth stuff
        return redirect(config.BASE_URL+'login/oauth2/auth?client_id='+config.oauth2_id +
                        '&response_type=code&redirect_uri='+config.oauth2_uri)

    msg = "Authentication error, please refresh and try again."
    return render_template("error.html", msg=msg)


# ============================================
# LTI Setup & Config
# ============================================

if __name__ == "__main__":
    app.debug = True
    app.secret_key = config.secret_key
    app.run(host="0.0.0.0", port=config.port)
