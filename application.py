import json
import random
import string

import httplib2
import requests
from flask import redirect, flash, Flask, render_template, make_response
from flask import request, url_for, jsonify
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import SingletonThreadPool

from models import Base, User, Item

auth = HTTPBasicAuth()

app = Flask(__name__)
app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits)
                         for x in range(32))

engine = create_engine('sqlite:///catalog.db' + '?check_same_thread=False',
                       poolclass=SingletonThreadPool)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open('client_secret.json', 'r')
                       .read())['web']['client_id']


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    auth_code = request.data

    if provider == 'google':
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                'client_secret.json', scope=''
            )
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads((h.request(url, 'GET')[1]).decode())
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for the user.
        user_id = credentials.id_token['sub']
        if result['user_id'] != user_id:
            response = make_response(
                json.dumps(
                    "Token's user ID doesn't match given user ID."
                ), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 401)
            print("Token's client ID does not match app's.")
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check if user is already logged in
        stored_credentials = login_session.get('credentials')
        stored_user_id = login_session.get('user_id')
        if stored_credentials is not None and user_id == stored_user_id:
            response = make_response(json.dumps(
                'Current user already connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in session for later use
        login_session['credentials'] = credentials.token_uri
        login_session['user_id'] = user_id

        # Once access tokens successfully received from google,
        # access user information from google

        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        login_session['username'] = data['name']
        login_session['email'] = data['email']

        # see if user exists, retrieve User and save to user variable,
        # if it doesn't make a new one
        user = session.query(User).filter_by(
            email=login_session['email']).first()
        if not user:
            user = User(username=login_session['username'],
                        email=login_session['email'])
            session.add(user)
            session.commit()

        output = '<h2>Welcome %s</h2>' % login_session['username']
        return output

    else:
        return 'Unrecognised Provider'


@app.route('/logout')
def logout():
    """
    User is logged out by signOut() function in script.
    This method clears the login_session.
    """
    try:
        access_token = login_session['credentials']
    except KeyError:
        return redirect(url_for('homepage'))
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    del login_session['credentials']
    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    return redirect(url_for('homepage'))


@app.route('/')
def homepage():
    items = session.query(Item).all()
    user = None
    if 'username' in login_session:
        user = login_session['username']
    logged_in = False
    if 'email' in login_session:
        logged_in = True
    return render_template('landing_page.html', items=items,
                           logged_in=logged_in, user=user)


@app.route('/category/<category_name>/')
def category_view(category_name):
    logged_in = False
    user = None
    if 'email' in login_session:
        logged_in = True
        user = login_session['username']

    items = session.query(Item).filter(
        Item.category.endswith(category_name)).all()
    return render_template(
        'category_list.html', items=items, logged_in=logged_in, user=user)


@app.route('/detail/<int:pk>/')
def item_detail(pk):
    logged_in = False
    user = None
    if 'email' in login_session:
        logged_in = True
        user = login_session['username']

    item = session.query(Item).get(pk)
    return render_template('item_detail.html', item=item,
                           logged_in=logged_in, user=user)


@app.route('/add/', methods=['GET', 'POST'])
def add_item():
    logged_in = False
    if 'email' in login_session:
        logged_in = True
    else:
        flash('Login Required for that action.')
        return redirect(url_for('homepage'))

    # if request object contains form, handle new item logic, else render form
    if request.form:
        item_name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        user_id = (session.query(User).filter_by(
            email=login_session['email']).one())
        new_item = Item(item_name=item_name, description=description,
                        category=category, user=user_id)
        session.add(new_item)
        session.commit()

        # redirect to homepage
        return redirect(url_for('homepage'))
    else:
        return render_template('add_item.html', logged_in=logged_in)


@app.route('/edit/<int:pk>/', methods=['GET', 'POST'])
def edit_item(pk):
    logged_in = False
    if 'email' in login_session:
        logged_in = True
    else:
        flash('Login Required for that action.')
        return redirect(url_for('homepage'))

    # if request object contains form, edit item, else render form
    item = session.query(Item).get(pk)
    if request.form:
        new_item_name = request.form.get('name')
        new_description = request.form.get('description')
        new_category = request.form.get('category')
        # replace values
        item.item_name = new_item_name
        item.description = new_description
        item.category = new_category
        session.commit()

        # redirect to homepage
        return redirect(url_for('homepage'))
    else:
        return render_template('edit_item.html', item=item,
                               logged_in=logged_in)


@app.route('/delete/<int:pk>/', methods=['GET', 'POST'])
def delete_item(pk):
    logged_in = False
    if 'email' in login_session:
        logged_in = True
    else:
        flash('Login Required for that action.')
        return redirect(url_for('homepage'))

    # if request object contains form, delete item, else render form
    item = session.query(Item).get(pk)
    if request.form:
        session.delete(item)
        session.commit()

        # redirect to homepage
        return redirect(url_for('homepage'))
    else:
        return render_template('delete_item.html', item=item,
                               logged_in=logged_in)


@app.route('/catalog/items/JSON')
def item_catalog_json():
    items = session.query(Item).all()
    logged_in = False
    if 'email' not in login_session:
        # redirect to homepage
        flash('Login Required for that action.')
        return redirect(url_for('homepage'))

    return jsonify(catalog_items=[i.serialize for i in items])


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
