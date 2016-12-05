# Documentation for Faculty Resources

## Dev Key
- You will need a dev key for OAuth. It can be generated on a local version of canvas for dev and testing. To get a local version of Canvas, check out [our Docker guide][1]. To get one for ***REMOVED*** or ***REMOVED***, ask the LMS admins.
    - You can generate a key on your local version by going to **Courses / Site Admin / Developer Keys** in your local version of Canvas. You'll need to have your redirect URI **(oauth2_uri)** ready, since you need it to make the key. If using Docker, make sure the urls are **http** instead of **https**. When you make a key, copy the ID to **oauth2_id** and the key into **oauth2_key** in your settings file.

## Virtual Environment
- Create a virtual environment and initiate it.
``` 
virtualenv venv
source venv/bin/activate
```
- Install everything:
```
pip install -r requirements.txt
```

Keep whitelist.json in mind. What LTIs do you want the instructors and faculty to see?

## Create DB

- Change directory into the project folder. Create the database in python shell:
```
    from views import db
    db.create_all()
```
- If you want to look at your users table in the future, you can look at it in the python shell:
```
    from views import Users
    Users.query.all()
```

## Run the App

- Run the views script while your virtual environment is active.
```
python views.py
```
- Go to the /xml page, http://0.0.0.0:8080/xml by default
- Copy the xml, install it into a test course. If you're using Docker, don't forget that it will only work on your Docker instance because of the dev key.

[1]: https://***REMOVED***/snippets/73 "Docker Guide"