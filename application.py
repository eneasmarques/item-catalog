#!/usr/bin/python3
import json
import os
import random
import requests
import string
import httplib2

from flask import Flask, render_template, request, flash
from flask import redirect, jsonify, url_for, make_response
from flask import session as login_session

from urllib.parse import urlencode

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from database_setup import Base, Restaurant, MenuItem, Users
from config_db import DATABASE_URL

# Google's Client ID
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


app = Flask(__name__)

engine = create_engine(DATABASE_URL)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    # Detect login status
    # login_status = None
    # if 'email' in login_session:
    #     login_status = True
    # print(login_status)
    # Generate state token for Google Sign-In
    # state = ''.join(random.choice(string.ascii_uppercase + string.digits)
    #                 for x in range(32))
    # login_session['state'] = state
    restaurant = session.query(Restaurant).first()
    # return "This page will show all my restaurants"
    return redirect(url_for('showMenu', restaurant_id=restaurant.id))


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Create a new restaurant
@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if request.method == 'POST':
        newRestaurant = Restaurant(name=request.form['name'])
        session.add(newRestaurant)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')
    # return "This page will be for making a new restaurant"


# Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    print(restaurant_id, editedRestaurant.name)
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            print(editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template(
            'editRestaurant.html', restaurant=editedRestaurant)

    # return 'This page will be for editing restaurant %s' % restaurant_id


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        session.commit()
        return redirect(
            url_for('showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template(
            'deleteRestaurant.html', restaurant=restaurantToDelete)
    # return 'This page will be for deleting restaurant %s' % restaurant_id


# Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurants = session.query(Restaurant).all()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()

    login_status = None
    if 'email' in login_session:
        login_status = True

    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return render_template('menu.html', items=items, restaurant=restaurant, login_status=login_status,restaurants=restaurants)
    # return 'This page is the menu for restaurant %s' % restaurant_id


# Create a new menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form[
                           'description'], price=request.form['price'], course=request.form['course'], restaurant_id=restaurant_id)
        session.add(newItem)
        session.commit()

        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


# Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['name']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        login_status = None
        if 'email' in login_session:
            login_status = True
        return render_template(
            'editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem, login_status=login_status)

    # return 'This page is for editing menu item %s' % menu_id


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete)
    # return "This page is for deleting menu item %s" % menu_id


def getUserInfo(user_id):
    user = session.query(Users).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    try:
        user = session.query(Users).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


def createUser(login_session):
    newUser = Users(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(Users).filter_by(email=login_session['email']).one()
    return user.id
   

# Connect to Google Account
@app.route('/google_connect', methods=['POST'])
def google_connect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

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

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
  
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
   
    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id
   
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print("Google Connect9")

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    print(login_session['email'])
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['credentials'] = credentials.token_uri
    login_session['user_id'] = user_id

    flash("You are now logged in as %s" % login_session['username'])
    print("done!")
    output = 'ok'
    return output

@app.route('/logout')
@app.route('/gdisconnect')
def gdisconnect():
    """App route function to disconnect from Google login."""
    try:
        access_token = login_session['username']
    except KeyError:
        print('Failed to get access token')
        flash('Failed to get access token')
        return redirect(url_for('showRestaurants'))
    print("User's name was {}.".format(login_session['username']))
    if access_token is None:
        print('Access Token is None')
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    del login_session['google_id']
    del login_session['access_token']

    print('Successfully logged out.')
    flash('Successfully logged out.')
    return redirect(url_for('showRestaurants'))


if __name__ == '__main__':
    app.secret_key = 'ycx5M8nv2yoXVAUed69f0kha'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000, threaded=False)
