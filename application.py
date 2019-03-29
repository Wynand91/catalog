import random, string

from flask import Flask, render_template
from flask import request
from flask import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import SingletonThreadPool

from models import Base, User, Item

from flask_httpauth import HTTPBasicAuth
import json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests
auth = HTTPBasicAuth()

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db'+'?check_same_thread=False', poolclass=SingletonThreadPool)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

@auth.verify_password
def verify_password(username_or_token, password):
    # Check first if it is a token
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):

    # auth_code = request.json.get('auth_code')
    # ding hierbo werk nie, toe ry ek maar die request data hier onder?
    print(request.data)

    # if provider == 'google':
    #     try:
    #         # Upgrade the authorization code into a credentials object
    #         oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    #         oauth_flow.redirect_uri = 'postmessage'
    #         credentials = oauth_flow.step2_exchange(auth_code)
    #     except FlowExchangeError:
    #         response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
    #         response.headers['Content-Type'] = 'application/json'
    #         return response
    #
    #     # Check that the access token is valid.
    #     access_token = credentials.access_token
    #     url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    #     h = httplib2.Http()
    #     result = json.loads(h.request(url, 'GET')[1])
    #     # If there was an error in the access token info, abort.
    #     if result.get('error') is not None:
    #         response = make_response(json.dumps(result.get('error')), 500)
    #         response.headers['Content-Type'] = 'application/json'
    #
    #     # Once access tokens successfully received from google, Find User or make a new one
    #     # and access user information from google
    #
    #     # Get user info
    #     h = httplib2.Http()
    #     userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    #     params = {'access_token': credentials.access_token, 'alt': 'json'}
    #     answer = requests.get(userinfo_url, params=params)
    #
    #     data = answer.json()
    #
    #     name = data['name']
    #     # email = data['email']
    #
    #     # see if user exists retrieve User and save to user variable, if it doesn't make a new one
    #     user = session.query(User).filter_by(email=email).first()
    #     if not user:
    #         user = User(username=name)
    #         session.add(user)
    #         session.commit()
    #
    #     # Make token with generate_auth_token method found in models
    #     token = user.generate_auth_token(600)
    #
    #     # Send back token to the client
    #     return jsonify({'token': token.decode('ascii')})
    #
    # else:
    #     return 'Unrecognised Provider'


@app.route('/')
def homepage():
    items = session.query(Item).all()
    return render_template('landing_page.html', items=items)


@app.route('/category/<category_name>/')
def category_view(category_name):
    items = session.query(Item).filter(Item.category.endswith(category_name)).all()
    return render_template('category_list.html', items=items)


@app.route('/detail/<int:pk>/')
def item_detail(pk):
    item = session.query(Item).get(pk)
    return render_template('item_detail.html', item=item)


@app.route('/add/', methods=['GET', 'POST'])
def add_item():
    # if request object contains form, handle new item logic, else render form
    if request.form:
        item_name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        new_item = Item(item_name=item_name, description=description,
                        category=category, user=user)
        session.add(new_item)
        session.commit()

        # get new list of items and render landing page
        items = session.query(Item).all()
        return render_template('landing_page.html', items=items)
    else:
        return render_template('add_item.html')


@app.route('/edit/<int:pk>/', methods=['GET', 'POST'])
def edit_item(pk):
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

        # get new list of items and render landing page
        items = session.query(Item).all()
        return render_template('landing_page.html', items=items)
    else:
        return render_template('edit_item.html', item=item)


@app.route('/delete/<int:pk>/', methods=['GET', 'POST'])
def delete_item(pk):
    # if request object contains form, delete item, else render form
    item = session.query(Item).get(pk)
    if request.form:
        session.delete(item)
        session.commit()

        # get new list of items and render landing page
        items = session.query(Item).all()
        return render_template('landing_page.html', items=items)
    else:
        return render_template('delete_item.html', item=item)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
