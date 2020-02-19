from flask import (
    Flask,
    abort,
    request,
    jsonify,
    render_template
)

from Crypto.PublicKey import RSA

import sqlite3

PORT=5000

db_path = "../../pbox.db"

db_conn = sqlite3.connect(db_path)
db = db_conn.cursor()

PK_STATUS_OK=0
PK_STATUS_REVOKED=1


# Servers
db.execute('''CREATE TABLE IF NOT EXISTS users (username text primary key unique)''')
db.execute('''CREATE TABLE IF NOT EXISTS public_keys (key_id integer primary key autoincrement, username text, public_key text, status int)''')
db.execute('''CREATE TABLE IF NOT EXISTS ips (key_id integer primary key autoincrement, username text, ip text)''')
# Account

db_conn.close()

# Create the application instance
app = Flask(__name__, template_folder="templates")

# Create a URL route in our application for "/"

@app.route('/api/version')
def get_version():
    """
    Return the version of the API.

    :return:        the version.
    """
    f = open("version.txt", 'r')
    version = f.readline().strip('\n')
    f.close()
    return jsonify({"version": version})


@app.route('/api/users/<string:user_id>')
def get_user(user_id):
    """
    Method to know if a user exist or not. Will be used during the registration.
    Therefor there is no authentication.

    :return:        200 if exists, 404 if not
    """

    db_conn = sqlite3.connect(db_path)
    db = db_conn.cursor()
    status = "free"
    try:
        for row in db.execute("SELECT username FROM users WHERE username=?", [user_id]):
            status = "taken"
        db_conn.close()
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)
    return jsonify({'user':{'username':user_id, 'status':status}})

@app.route('/api/users', methods=['POST'])
def add_user():
    """
    Register a new user into the system.
    A free username and a public key must be provided.

    :return:        200 if the registration processed as expected
    """
    if not request.json:
        abort(400)

    db_conn = sqlite3.connect(db_path)
    db = db_conn.cursor()

    username = request.json['username']
    public_key = request.json['public_key']

    try:
        db.execute("INSERT INTO users (username) VALUES (?)", [username])
        db.execute("INSERT INTO public_keys (username, public_key, status) VALUES (?,?,?)", [username, public_key, PK_STATUS_OK])
        db_conn.commit()
        db_conn.close()
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)
    return jsonify({'success':True})

@app.route('/api/users/<string:user_id>/keys')
def get_keys(user_id):
    """
    Return the list of valid public keys of the said user.
    Must be authenticated to access.
    Access from everyone.

    :return:        the list of valid public keys
    """

    db_conn = sqlite3.connect(db_path)
    db = db_conn.cursor()
    keys = []
    try:
        for row in db.execute("SELECT public_key FROM public_keys WHERE username=? AND status=?", [user_id, PK_STATUS_OK]):
            keys.append({"public": row[0]})
        db_conn.close()
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)
    if(keys == []):
        abort(404)
    return jsonify({'user':{'username':user_id, 'keys':keys}})

@app.route('/api/users/<string:user_id>/keys', methods=['PUT'])
def update_keys(user_id):
    """
    Add or revoke a public key.
    Must be authenticated.
    Access only from said user.

    :return:        status and eventual error messages
    """

    if not request.json:
        abort(400)

    new_pub_keys = request.json["public_keys"]

    db_conn = sqlite3.connect(db_path)
    db = db_conn.cursor()
    db_pub_keys = []
    try:
        for row in db.execute("SELECT public_key FROM public_keys WHERE username=? AND status=?;", [user_id, PK_STATUS_OK]):
            db_pub_keys.append(row[0])
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)

    to_add = []
    to_revoke = []

    # Put the keys not present in the database in the list of keys to add
    for new_key in new_pub_keys:
        if(new_key not in db_pub_keys):
            to_add.append((user_id, new_key, PK_STATUS_OK))
    # Put the keys not in the new list in the list of keys to revoke
    for db_key in db_pub_keys:
        if(db_key not in new_pub_keys):
            to_revoke.append((PK_STATUS_REVOKED, user_id, db_key))

    try:
        db.executemany('INSERT INTO public_keys (username, public_key, status) VALUES (?,?,?);', to_add)
        db.executemany('UPDATE public_keys SET status=? WHERE username=? AND public_key=?;', to_revoke)
        db_conn.commit()
        db_conn.close()
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)

    return jsonify({'status':True})

@app.route('/api/users/<string:user_id>/endpoints')
def get_endpoints(user_id):
    """
    Return the list IPs of the said user.
    Must be authenticated to access.
    Access only from said user.

    :return:        the list of IPs
    """

    db_conn = sqlite3.connect(db_path)
    db = db_conn.cursor()
    ips = []
    try:
        for row in db.execute("SELECT ip FROM ips WHERE username=?", [user_id]):
            ips.append({"address": row[0]})
        db_conn.close()
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)
    return jsonify({'user':{'username':user_id, 'ips':ips}})

@app.route('/api/users/<string:user_id>/endpoints', methods=['PUT'])
def update_endpoints(user_id):
    """
    Update the list of public IPs.
    Must be authenticated to access.
    Access only from said user.

    :return:        the list of IPs
    """

    if not request.json:
        abort(400)

    new_ips = request.json["ips"]

    db_conn = sqlite3.connect(db_path)
    db = db_conn.cursor()
    db_ips = []
    try:
        for row in db.execute("SELECT ip FROM ips WHERE username=?;", [user_id]):
            db_ips.append(row[0])
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)

    to_add = []
    to_delete = []

    # Put the ips not present in the database in the list of ips to add
    for new_ip in new_ips:
        if(new_ip not in db_ips):
            to_add.append((user_id, new_ip))
    # Put the ips not in the new list in the list of ips to delete
    for db_ip in db_ips:
        if(db_ip not in new_ips):
            to_delete.append((user_id, db_ip))

    try:
        db.executemany('INSERT INTO ips (username, ip) VALUES (?,?);', to_add)
        db.executemany('DELETE FROM ips WHERE username=? AND ip=?;', to_delete)
        db_conn.commit()
        db_conn.close()
    except sqlite3.IntegrityError:
        db_conn.close()
        abort(400)
    return jsonify({'status':True})


# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=PORT)
