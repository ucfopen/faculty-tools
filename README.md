# Documentation for Faculty Resources

- You will need a dev key for OAuth. It can be generated on a local version of canvas. To get a local version of canvas, check out [our Docker guide][1].
- Create a virtual environment. Install everything:

```
pip -r install requirements.txt
```

- Keep whitelist.json in mind. What LTIs do you want the instructors and faculty to see?
- Create a database with a table called main:

```
    CREATE TABLE main (primary_key INTEGER PRIMARY KEY, user_id NUMERIC, refresh_key TEXT, expires_in TEXT)
```

- Run the views script.

```
python views.py
```

- Go to the /xml page, http://0.0.0.0:8080/xml by default
- Copy the xml, install it into a test course. If you're using docker, don't forget that it will only work on your docker instance because of the dev key.

[1]: https://***REMOVED***/snippets/73 "Docker Guide"