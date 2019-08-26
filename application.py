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


# Irá redirecionar para que seja mostrado todos os Restaurantes e Itens
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurant = session.query(Restaurant).first()
    return redirect(url_for('showMenu', restaurant_id=restaurant.id))


# JSON com o Menu de um Restaurante
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# JSON com todos os Itens de um Menu
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


# JSON com todos os Restaurantes
@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Cria um novo Restaurante
@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newRestaurant)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')
    # return "This page will be for making a new restaurant"


# Edita um Restaurante
@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if login_session['user_id'] == editedRestaurant.user_id:
            if request.form['name']:
                editedRestaurant.name = request.form['name']
                return redirect(url_for('showRestaurants'))
        else:
            flash("You are not allowed to edit this item.")
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        login_status = None
        if 'email' in login_session:
            editedRestaurant = session.query(Restaurant).filter_by(
                id=restaurant_id).one()
            if editedRestaurant.user_id == login_session['user_id']:
                login_status = True

        return render_template(
            'editRestaurant.html',
            restaurant=editedRestaurant,
            login_status=login_status)

    # return 'This page will be for editing restaurant %s' % restaurant_id


# Delete um Restaurante
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if login_session['user_id'] == restaurantToDelete.user_id:
            session.delete(restaurantToDelete)
            session.commit()
            return redirect(
                url_for('showRestaurants', restaurant_id=restaurant_id))
        else:
            flash("You are not allowed to delete this item.")
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        login_status = None
        if 'email' in login_session:
            editedRestaurant = session.query(Restaurant).filter_by(
                id=restaurant_id).one()
            if editedRestaurant.user_id == login_session['user_id']:
                login_status = True

        return render_template(
            'deleteRestaurant.html',
            restaurant=restaurantToDelete,
            login_status=login_status)
    # return 'This page will be for deleting restaurant %s' % restaurant_id


# Mostra todos os Restaurantes e o primeiro Menu do mesmo
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurants = session.query(Restaurant).all()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()

    # Verifica se está logado
    login_status = None
    if 'email' in login_session:
        login_status = True

    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return render_template('menu.html', items=items, restaurant=restaurant,
                           login_status=login_status, restaurants=restaurants)


# Ciar um novo Item do Menu
@app.route(
    '/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            course=request.form['course'],
            restaurant_id=restaurant_id,
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()

        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


# Edita um Item de um Menu
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        if login_session['user_id'] == editedItem.user_id:
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
            flash("You are not allowed to edit this item.")
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        # Verifica se usuário está logado
        login_status = None
        if 'email' in login_session:
            editedMenuItem = session.query(MenuItem).filter_by(
                id=menu_id).one()
            if editedMenuItem.user_id == login_session['user_id']:
                login_status = True

        return render_template(
            'editmenuitem.html', restaurant_id=restaurant_id,
            menu_id=menu_id, item=editedItem,
            login_status=login_status)


# Deleta um Item do Menu
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        if login_session['user_id'] == itemToDelete.user_id:
            session.delete(itemToDelete)
            session.commit()
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
        else:
            flash("You are not allowed to delete this item.")
            return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        login_status = None
        if 'email' in login_session:
            editedMenuItem = session.query(MenuItem).filter_by(
                id=menu_id).one()
            if editedMenuItem.user_id == login_session['user_id']:
                login_status = True

        return render_template('deleteMenuItem.html',
                               item=itemToDelete,
                               login_status=login_status)


# Retorna informações do usuário
def getUserInfo(user_id):
    user = session.query(Users).filter_by(id=user_id).one_or_none()
    return user


# Retorna ID do usuário
def getUserID(email):
    try:
        user = session.query(Users).filter_by(email=email).one()
        return user.id
    except Exception:
        return None

# Cria um novo Usuário


def createUser(login_session):
    newUser = Users(name=login_session['username'], email=login_session[
        'email'])
    session.add(newUser)
    session.commit()
    user = session.query(Users).filter_by(email=login_session['email']).one()
    return user.id


# Conecta em uma conta do Google
@app.route('/google_connect', methods=['POST'])
def google_connect():
    # Valida o token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Código de autorização
    code = request.data

    try:
        # Atualiza o código de autorização no client_secrets
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verifica se o token é válido
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads((h.request(url, 'GET')[1]).decode())

    # Aborta se houver erro nas informações do token de acesso
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verifica se o token de acesso é usado para o usuário pretendido.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verifica se o token de acesso é válido para este aplicativo.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Armazena o token de acesso na sessão para uso posterior
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Obtem informações do usuário
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['credentials'] = credentials.token_uri
    login_session['user_id'] = user_id

    flash("You are now logged in as %s" % login_session['username'])
    output = 'ok'
    return output


# Desconectar do login do Google
@app.route('/logout')
@app.route('/gdisconnect')
def gdisconnect():
    try:
        access_token = login_session['username']
    except KeyError:
        flash('Failed to get access token')
        return redirect(url_for('showRestaurants'))
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    del login_session['google_id']
    del login_session['access_token']

    flash('Successfully logged out.')
    return redirect(url_for('showRestaurants'))


if __name__ == '__main__':
    app.secret_key = 'ycx5M8nv2yoXVAUed69f0kha'
    app.debug = True
    app.run(host='0.0.0.0', port=5000, threaded=False)
