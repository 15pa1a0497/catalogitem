from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Style, Commodity, User
# Import Login session
from flask import session as login_session
import random
import string
# imports for gconnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
# import login decorator
from functools import wraps
from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

engine = create_engine('sqlite:///style.db')
Base.metadata.bind = engine


DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@app.route('/login')
def showlogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application-json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # upgrade the authorization code in credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade\
                                            the authorization code'), 401)
        response.headers['Content-Type'] = 'application-json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode("utf-8"))
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
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
    # Access token within the app
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user\
                                            is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    response = make_response(json.dumps('Succesfully connected users'), 200)

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # See if user exists or if it doesn't make a new one
    print('User email is' + str(login_session['email']))
    user_id = getUserID(login_session['email'])
    if user_id:
        print('Existing user#' + str(user_id) + 'matches this email')
    else:
        user_id = createUser(login_session)
        print('New user_id#' + str(user_id) + 'created')
        login_session['user_id'] = user_id
        print('Login session is tied to :id#' + str(login_session['user_id']))

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; height: 200px;border-radius:100px;- \
      webkit-border-radius:100px;-moz-border-radius: 100px;">'
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).first()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).first()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session.
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected User
    access_token = login_session.get('access_token')
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.c\
           om/o/oauth2/revoke?token = %s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is')
    print(result)
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke\
                                            token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
            flash("you have succesfully been logout")
            return redirect(url_for('showStyles'))
    else:
        flash("you were not logged in")
        return redirect(url_for('showStyles'))


@app.route('/style/<int:style_id>/commodity/JSON')
def styleCommodityJSON(style_id):
    style = session.query(Style).filter_by(id=style_id).one()
    details = session.query(Commodity).filter_by(
        style_id=style_id).all()
    return jsonify(Commodity=[i.serialize for i in details])


@app.route('/style/<int:style_id>/details/<int:details_id>/JSON')
def commoditiesJSON(style_id, details_id):
    Commodity_Details = session.query(Commodity).filter_by(id=details_id).one()
    return jsonify(Commodity_Details=Commodity_Details.serialize)


@app.route('/style/JSON')
def stylesJSON():
    styles = session.query(Style).all()
    return jsonify(styles=[r.serialize for r in styles])
# Show all styles


@app.route('/')
@app.route('/style/')
def showStyles():
    session1 = DBSession()
    styles = session1.query(Style).all()
    # return "This page will show all my styles"
    session1.close()
    return render_template('styles.html', styles=styles)


# Create a new style
@app.route('/style/new/', methods=['GET', 'POST'])
def newStyle():
    session2 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newStyle = Style(name=request.form['name'],
                         user_id=login_session['user_id'])
        session2.add(newStyle)
        session2.commit()
        session2.close()
        return redirect(url_for('showStyles'))
    else:
        session2.close()
        return render_template('newStyle.html')
    # return "This page will be for making a new style"

# Edit a style


@app.route('/style/<int:style_id>/edit/', methods=['GET', 'POST'])
def editStyle(style_id):
    session3 = DBSession()
    editStyle = session3.query(Style).filter_by(id=style_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            print(editStyle.name)
            editStyle.name = request.form['name']
            session3.add(editStyle)
            session3.commit()
            session3.close()
            return redirect(url_for('showStyles', style_id=style_id))
    else:
        session3.close()
        return render_template(
            'editStyle.html', style_id=style_id, style=editStyle)

    # return 'This page will be for editing style %s' % style_id

# Delete a style


@app.route('/style/<int:style_id>/delete/', methods=['GET', 'POST'])
def deleteStyle(style_id):
    session4 = DBSession()
    deleteStyle = session4.query(
        Style).filter_by(id=style_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        session4.delete(deleteStyle)
        session4.commit()
        session4.close()
        return redirect(
            url_for('showStyles', style_id=style_id))
    else:
        session4.close()
        return render_template(
            'deleteStyle.html', style_id=style_id, style=deleteStyle)
    # return 'This page will be for deleting style %s' % style_id


# Show a style commodity
@app.route('/style/<int:style_id>/')
@app.route('/style/<int:style_id>/commodity/')
def showCommodity(style_id):
    session5 = DBSession()
    style = session5.query(Style).filter_by(id=style_id).one()
    details = session5.query(Commodity).filter_by(style_id=style_id).all()
    session5.close()
    for d in details:
        print(d.name)
    return render_template('commodity.html', details=details, style=style)
    # return 'This page is the commodity for style %s' % style_id

# Create a new commodity details


@app.route(
    '/style/<int:style_id>/commodity/new/', methods=['GET', 'POST'])
def newCommodity(style_id):
    session6 = DBSession()
    style = session6.query(Style).filter_by(id=style_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newStyle = Commodity(name=request.form['name'],
                             description=request.form['description'],
                             price=request.form['price'],
                             materialtype=request.form['materialtype'],
                             style_id=style.id,
                             user_id=style.user_id)
        session6.add(newStyle)
        session6.commit()
        session6.close()
        return redirect(url_for('showCommodity', style_id=style_id))
    else:
        return render_template('newCommodity.html', style_id=style_id)

    return render_template('newCommodity.html')
    # return 'This page is for making a new commodity details for style %s'
    # %style_id

# Edit a commodity details


@app.route('/style/<int:style_id>/commodity/<int:commodity_id>/edit',
           methods=['GET', 'POST'])
def editCommodity(style_id, commodity_id):
    session7 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    editCommodity = session7.query(Commodity).filter_by(id=commodity_id).one()
    style = session7.query(Style).filter_by(id=style_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editCommodity.name = request.form['name']
        if request.form['description']:
            editCommodity.description = request.form['name']
        if request.form['price']:
            editCommodity.price = request.form['price']
        if request.form['materialtype']:
            editCommodity.materialtype = request.form['materialtype']
        session7.add(editCommodity)
        session7.commit()
        session7.close()
        return redirect(url_for('showCommodity', style_id=style_id))
    else:
        return render_template('editcommodity.html', style_id=style_id,
                               commodity_id=commodity_id,
                               details=editCommodity)

    # return 'This page is for editing commodity details %s' % commodity_id

# Delete a commodity details


@app.route('/style/<int:style_id>/commodity/<int:commodity_id>/delete',
           methods=['GET', 'POST'])
def deleteCommodity(style_id, commodity_id):
    session8 = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    editCommodity = session8.query(Commodity).filter_by(id=commodity_id).one()
    style = session8.query(Style).filter_by(id=style_id).one()
    deleteCommodity = session8.query(Commodity).filter_by(id=commodity_id).one()
    if request.method == 'POST':
        session8.delete(deleteCommodity)
        session8.commit()
        session8.close()
        return redirect(url_for('showCommodity', style_id=style_id))
    else:
        return render_template('deleteCommodity.html', style_id=style_id,
                               commodity_id=commodity_id,
                               details=deleteCommodity)
    # return "This page is for deleting commodity details %s" % commodity_id


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
