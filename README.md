# Documentation for Faculty Tools

## Settings

Create a new `settings.py` file from the template

```sh
cp settings.py.template settings.py
```

Edit `settings.py` to configure the application. All fields are required,
unless specifically noted.

## Developer Key

You will need a developer key for the OAuth2 flow. Check out the [Canvas
documentation for creating a new developer key](https://community.canvaslms.com/docs/DOC-12657-4214441833)

- Have your redirect URI (`oauth2_uri`) ready, since you need it to make
  the key.
- When you make a key, copy the ID to `oauth2_id` and the key into `oauth2_key`
  in your settings file.

## Tool Whitelist

Add the tools you want instructors and faculty to see to `whitelist.json`.

```json
[
    {
        # The name of the tool from within the Settings page
        "name": "Installed Tool Name",
        # The unique tool id, not currently used
        "tool_id": "tool_id",
        # Allows viewable name to be different from installed name, ie: Attendance vs. RollCall
        "display_name": "Name to Display",
        # Short description of the tool to be displayed to the user
        "desc": "Tool Description",
        # Filename of screenshot. Must be in static/img/screenshots
        "screenshot": "screenshot.png",
        # Filename of logo. Must be in static/img/logos
        "logo": "logo.svg",
        # Link to the tool's documentation. Appears as the Learn More button
        "docs_url": "https://example.com/tool/docs/",
        # Turns off/on launch button inside Faculty Tools - Useful for docs
        "is_launchable": true,
        # What category to put the tool in. Options: Course Tool, Assignment Editor, Rich Content Editor
        "category": "Course Tool",
        # For future use
        "filter_by": ["all"],
        "allowed_roles": [""],
    },
]
```

## Virtual Environment

Create a new virtual environment.

```sh
virtualenv env
```

Activate the environment.

```sh
source env/bin/activate
```

Install everything:

```sh
pip install -r requirements.txt
```

## Create DB

Change directory into the project folder. Create the database in python shell:

```sh
from lti import db
db.create_all()
```

If you want to look at your users table in the future, you can do so in the
python shell:

```python
from lti import Users
Users.query.all()
```

## Environment Variables

Set the flask app to `lti.py` and debug to true.

```sh
export FLASK_APP=lti.py
export FLASK_DEBUG=1
```

Alternatively, you can run the setup script to simultaneously setup environment
variables and the virtual environment.

```sh
source setup.sh
```

## Run the App

Run the lti script while your virtual environment is active.

```sh
flask run
```

Go to the /xml page, [http://0.0.0.0:5000/xml](http://0.0.0.0:5000/xml) by default

Copy the xml, install it into a course.
