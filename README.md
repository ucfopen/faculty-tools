[![Build Status](https://travis-ci.org/ucfopen/faculty-tools.svg?branch=master)](https://travis-ci.org/ucfopen/faculty-tools)
[![Coverage Status](https://coveralls.io/repos/github/ucfopen/faculty-tools/badge.svg?branch=master)](https://coveralls.io/github/ucfopen/faculty-tools?branch=master)
[![Join UCF Open Slack Discussions](https://ucf-open-slackin.herokuapp.com/badge.svg)](https://ucf-open-slackin.herokuapp.com/)

# Documentation for Faculty Tools

## Setting up Faculty Tools with Docker & Docker-Compose

First clone and setup the repo.

```sh
git clone git@github.com:ucfopen/faculty-tools.git
cd faculty-tools
cp whitelist.json.template whitelist.json
cp .env.template .env
```

### Environment Variables

Edit `.env` to configure the application. All fields are required,
unless specifically noted.

To create a good secure secret key, run this command:

```sh
docker-compose run --rm lti python -c "import os, binascii; print(binascii.b2a_base64(os.urandom(24)).decode('ascii'))" 
```

```sh
TOOL_TITLE=Faculty Tools # Window Title of Page
THEME_DIR= # Keep blank unless building out your own theme directory
BASE_CANVAS_SERVER_URL=https://example.com/ # the URL for your canvas server
SECRET_KEY=CHANGEME # Random key used to secure portions of Flask - Follow instructions above
LTI_KEY=key # Random key - This is public - Used to install LTI.
LTI_SECRET=secret # Random secret key - Used to install LTI.  Do not share!
OAUTH2_URI=http://127.0.0.1:9001/oauthlogin # URL of faculty tools oauthlogin page
OAUTH2_ID=CHANGEME # ID given by LMS Admins / Developer Key (API Key) page in Canvas
OAUTH2_KEY=CHANGEME # ID given by LMS Admins / Developer Key (API Key) page in Canvas
GOOGLE_ANALYTICS=GA-000000 # Your Google Analytics id.
DATABASE_URI=mysql://root:secret@db/faculty_tools # Your mysql connection string.

# config.py configuration settings
# config.Development for Dev, config.BaseConfig for production
CONFIG=config.DevelopmentConfig


# test_requirements for development / requirements.txt for production.
REQUIREMENTS=test_requirements.txt 

WHITELIST_JSON=whitelist.json # See below

```

## Developer Key -> API Key

You will need a developer key for the OAuth2 flow. Check out the [Canvas
documentation for creating a new developer key](https://community.canvaslms.com/docs/DOC-12657-4214441833)

- Have your redirect URI (`oauth2_uri`) ready, since you need it to make
  the key.
- When you make a key, copy the ID to `oauth2_id` and the key into `oauth2_key`
  in your settings file.

## Tool Whitelist

Add the tools you want instructors and faculty to see to `whitelist.json`.

```js
[
    {
        // The name of the tool from within the Settings page
        "name": "Installed Tool Name",
        // The unique tool id, not currently used
        "tool_id": "tool_id",
        // Allows viewable name to be different from installed name, ie: Attendance vs. RollCall
        "display_name": "Name to Display",
        // Short description of the tool to be displayed to the user
        "desc": "Tool Description",
        // Filename of screenshot. Must be in static/img/screenshots
        "screenshot": "screenshot.png",
        // Filename of logo. Must be in static/img/logos
        "logo": "logo.svg",
        // Link to the tool's documentation. Appears as the Learn More button
        "docs_url": "https://example.com/tool/docs/",
        // Turns off/on launch button inside Faculty Tools - Useful for docs
        "is_launchable": true,
        // What category to put the tool in. Options: Course Tool, Assignment Editor, Rich Content Editor
        "category": "Course Tool",
        // For future use
        "filter_by": ["all"],
        "allowed_roles": [""],
    },
]
```

## Create DB

We need to generate the database and tables for faculty tools to run properly.
The MySQL docker image automatically creates the user, password, and database
name set in the `docker-compose.yml` file.

```sh
docker-compose run --rm lti python
from lti import db
db.create_all()
```

If you want to look at your users table in the future, you can do so in the
python shell:

```python
docker-compose run lti python
from lti import Users
Users.query.all()
```

## Run the App

It's time to use docker-compose to bring up the application.

```sh
docker-compose up -d
```

Go to the /xml page, <http://127.0.0.1:9001/xml> by default.

Copy the xml, and install it into a course (Course->Settings->Apps).

## View the Logs

To view the logs while the application is running use this docker command:

```sh
docker-compose logs -f
```

## Stopping the App

To shutdown Faculty Tools

```sh
docker-compose down
```
