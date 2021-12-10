import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, \
    abort, render_template, flash, make_response
from flask_wtf.csrf import CSRFProtect
import base64

# Configuration
DATABASE = os.path.dirname(os.path.abspath(__file__)) + '/tmp/database.db'
DEBUG = False

UPLOAD_FOLDER = './upload'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config.from_object(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.jinja_env.autoescape = True
# Get a better secret key!
app.config.update(
    SECRET_KEY="This is a secret!!!",
)

csrf = CSRFProtect()
csrf.init_app(app)


# Requests
@app.before_request
def before_request():
    g.db = connect_db()
    allowed_routes = ['login', 'create', 'index']
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect('login')


@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


def connect_db():
    return sqlite3.connect(app.config['DATABASE'])


def get_env_dir():
    return os.path.dirname(os.path.abspath(__file__))


@app.route('/')
def index():
    response = make_response(render_template('index.html'))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/create', methods=['GET', 'POST'])
def create():
    error = None
    if request.method == 'POST':
        if request.form['username'] == "":
            error = 'Username needed'
        elif request.form['password'] == "" or request.form['repassword'] == "":
            error = 'Password needed'
        elif request.form['password'] != request.form['repassword']:
            error = 'Password is not the same as the retyped'
        else:
            username = str(request.form['username'])
            query = "select username from user where username = " + "'" + str(username) + "'"
            cur = g.db.execute(query)
            u = [dict(password=row[0]) for row in cur.fetchall()]
            if len(u) == 0:
                g.db.execute('insert into user (username, password, token) values (?, ?, ?)',
                             [request.form['username'], request.form['password'], ''])
                g.db.commit()

                flash('Successfully created - You can now login')
                return redirect(url_for('login'))
            else:
                error = 'Username is taken'

    response = make_response(render_template('create.html', error=error))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = g.db.execute("select password from user where username = '{}'".format(username))
        pass_db = [dict(password=row[0]) for row in cur.fetchall()]
        if pass_db[0].get('password') is None:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)
        p = pass_db[0].get('password')

        if p == password:
            cur = g.db.execute("select id from user where username = '{}'".format(username))
            rows = [dict(id=row[0]) for row in cur.fetchall()]
            user_id = rows[0].get('id')

            session['logged_in'] = True
            session['user_id'] = user_id
            flash('You were logged in')
            return redirect(url_for('profile'))
        else:
            error = 'Invalid username or password'

    response = make_response(render_template('login.html', error=error))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    flash('You were logged out')

    response = make_response(redirect(url_for('index')))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    g.db.execute(
        "insert into entries (title, text) values ('{}', '{}')".format(request.form['title'], request.form['text']))
    g.db.commit()
    flash('New entry was successfully posted')

    response = make_response(redirect(url_for('show_entries')))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = file.filename

            user_id = get_userid()

            g.db.execute('insert into images (image, user_id, filename) values (?, ?, ?)',
                         (base64.b64encode(file.read()), user_id, filename))
            g.db.commit()

            flash('uploaded image: %s' % filename)
            return redirect(url_for('profile'))
        else:
            flash('filetype not allowed')

    response = make_response(render_template('upload.html'))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


def blob_to_image(filename, ablob):
    folder = get_env_dir() + '/static/img/'
    with open(folder + filename, 'wb') as output_file:
        output_file.write(base64.b64decode(ablob))
    return filename


@app.route('/profile', methods=['GET'])
def profile():
    id = session.get('user_id')

    cur = g.db.execute("select id, image, filename from images where user_id = '{}'".format(id))
    images = [dict(image_id=row[0], image=blob_to_image(row[2], row[1])) for row in cur.fetchall()]

    cur = g.db.execute(
        "select images.id, images.image, images.filename from images inner join share on images.id = share.image_id where share.to_id = '{}'".format(
            id))
    shared_images = [dict(image_id=row[0], image=blob_to_image(row[2], row[1])) for row in cur.fetchall()]

    response = make_response(render_template('profile.html', images=images, shared_images=shared_images))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/showimage/<id>/', methods=['GET'])
def show_image(id):
    user_id = get_userid()
    if has_permission(id, user_id):
        cur = g.db.execute("select image, filename, user_id from images where id = {}".format(id))
        img = [dict(filename=row[1], image=blob_to_image(row[1], row[0]), user_id=row[2]) for row in cur.fetchall()]

        cur = g.db.execute('select id, username from user')
        usr = [dict(id=row[0], username=row[1]) for row in cur.fetchall()]

        cur = g.db.execute(
            "select share.id, user.username from share inner join user on user.id == share.to_id where from_id = {} and share.image_id = {}".format(
                user_id, id))
        share = [dict(id=row[0], username=row[1]) for row in cur.fetchall()]

        cur = g.db.execute(
            "select user.username, comments.comment from user inner join comments on user.id == comments.user_id where comments.image_id = {}".format(
                id))
        comments = [dict(username=row[0], comment=row[1]) for row in cur.fetchall()]

        response = make_response(render_template('image.html', imageid=id, image=img, usernames=usr, shares=share, comments=comments,
                               owner=img[0].get('user_id') == user_id))

        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['X-XSS-Protection'] = '1; mode=block'

        return response
    else:
        return redirect(url_for('no_way'))


def has_permission(img_id, user_id):
    cur = g.db.execute("select user_id from images where id = {}".format(img_id))
    img_user_id = [dict(user_id=row[0]) for row in cur.fetchall()]

    if user_id == img_user_id[0].get('user_id'):
        return True

    cur = g.db.execute(
        "select id from share where image_id = {} and to_id = {}".format(img_id, user_id))
    share = [dict(id=row[0]) for row in cur.fetchall()]

    if len(share) > 0:
        return True
    return False


@app.route('/shareimage', methods=['POST'])
def share_image():
    if request.method == 'POST':
        image_id = request.form['imageid']
        to_userid = request.form['userid']

        if has_permission(image_id, get_userid()):
            g.db.execute("insert into share (image_id, to_id, from_id) values ({}, {}, {})".format(image_id, to_userid,
                                                                                                   get_userid()))
            g.db.commit()
            flash('Image shared')

            response = make_response(redirect(url_for('show_image', id=image_id)))

            response.headers['Content-Security-Policy'] = "default-src 'self'"
            response.headers['X-XSS-Protection'] = '1; mode=block'

            return response


@app.route('/unshare', methods=['POST'])
def unshare():
    if request.method == 'POST':
        shared_id = request.form['shareduser']
        image_id = request.form['imageid']

        g.db.execute("delete from share where id = {}".format(shared_id))
        g.db.commit()
        flash('Image unshared')

        response = make_response(redirect(url_for('show_image', id=image_id)))

        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['X-XSS-Protection'] = '1; mode=block'

        return response
    else:
        return redirect(url_for('no_way'))


@app.route('/no_way', methods=['GET'])
def no_way():

    response = make_response(render_template('no_way.html'))

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


@app.route('/add_comment', methods=['POST'])
def add_comment():
    if request.method == 'POST':
        # TODO: needs to check for access
        image_id = request.form['imageid']
        userid = get_userid()
        comment = request.form['text']

        g.db.execute(
            "insert into comments (user_id, image_id, comment) values ({}, {}, '{}')".format(userid, image_id, comment))
        g.db.commit()
        flash('Added comment')

        response = make_response(redirect(url_for('show_image', id=image_id)))

        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['X-XSS-Protection'] = '1; mode=block'

        return response


def get_userid():
    return session.get('user_id')


@app.errorhandler(404)
def page_not_found(e):

    response = make_response(render_template('404.html'), 404)

    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
