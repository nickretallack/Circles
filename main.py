from flask import Flask, render_template as render, request,  g, redirect, session as web_session, url_for
from flaskext.sqlalchemy import SQLAlchemy
from flaskext.mail import Mail
from werkzeug import generate_password_hash, check_password_hash
from werkzeug.datastructures import MultiDict
from wtforms import *
from uuid import uuid4 

def make_invitation_id():
    return uuid4().hex

def required(result):
    if not result:
        abort(404)
    return result

def get_required(model, id):
    return required(db.session.query(model).filter_by(id=id).first())

app = Flask(__name__)
app.secret_key = 'seeeecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://nick@localhost/circles'

app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = True,
    MAIL_DEBUG = True,
    MAIL_USERNAME = 'nickretallack',
    MAIL_PASSWORD = 'Sporks27',
    DEFAULT_MAIL_SENDER = 'nickretallack@gmail.com',
    MAIL_FAIL_SILENTLY = False,
)
ADMINS = ['nickretallack@gmail.com']
db = SQLAlchemy(app)
mail = Mail(app)
#if not app.debug:
#    import logging
#    from logging.handlers import SMTPHandler
#    mail_handler = SMTPHandler('127.0.0.1',
#                               'server-error@example.com',
#                               ADMINS, 'YourApplication Failed')
#    mail_handler.setLevel(logging.ERROR)
#    app.logger.addHandler(mail_handler)

class AnonymousUser(object):
    id = 0
    

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    #current_location
    #current_icon
    created_at = db.Column(db.Date)

    #trusted_users = db.relationship('User', secondary='trust', backref='trusting_users') 

class PasswordCredentials(db.Model):
    __tablename__ = 'passwords'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    login = db.Column(db.String(80), unique=True, primary_key=True)
    hashed_password = db.Column(db.String(80))

    user = db.relationship(User, backref='credentials')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

class OpenIDCredentials(db.Model):
    __tablename__ = 'openids'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    openid = db.Column(db.String(80), primary_key=True)

class Location(db.Model):
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(80)) # (string for google maps)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class Trust(db.Model):
    __tablename__ = 'trusts'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    trusted_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'), primary_key=True)

    #user = db.relationship(User, backref='trusts')
    #circle = db.relationship(Circle, backref='trusts')

class Circle(db.Model):
    __tablename__ = 'circles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.Text)
    visibility = db.Column(db.String(20))
    gate = db.Column(db.String(20)) # (anyone, chain-of-trust)
    uploaded_at = db.Column(db.Date)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    creator = db.relationship(User, backref='circles_created')

    @property
    def url(self):
        return url_for('show_circle', id=self.id)

class CircleMembership(db.Model):
    __tablename__ = 'user_circles'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    nickname = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Date)

    user = db.relationship(User, backref='memberships')
    circle = db.relationship(Circle, backref='memberships')

class Photo(db.Model):
    __tablename__ = 'photos'
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(80))
    filename = db.Column(db.String(80)) # - sanitized by werkzeug.  Place photos in <hash>/filename
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id')) # -- handled by a relationship?  *shrug*  nah we can special case this
    uploaded_at = db.Column(db.Date)

class PhotoRelationship(db.Model): # - tags users in photos
    __tablename__ = 'photo_relationships'
    photo_id = db.Column(db.Integer, db.ForeignKey('photos.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    relationship = db.Column(db.String(20), primary_key=True) # (uploaded, drew, for, in, from)

class PhotoCircles(db.Model): # -- determines whether the photo is visible to a given circle
    __tablename__ = 'photo_circles'
    photo_id = db.Column(db.Integer, db.ForeignKey('photos.id'), primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'), primary_key=True)
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussions.id'))

    photo = db.relationship(Photo, backref='photo_circles')
    circle = db.relationship(Circle, backref='photo_circles')
    discussion = db.relationship('Discussion', backref='photo_circles')

    def __init__(self, *args, **kwargs):
        super(Circle, self).__init__(*args, **kwargs)
        self.discussion = Discussion()

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussions.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id')) # (can be null) - for threading
    text = db.Column(db.Text)
    date = db.Column(db.Date) # (for ordering)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    parent = db.relationship('Comment', backref='children', remote_side=[id])
    discussion = db.relationship('Discussion', backref='comments')
    user = db.relationship(User, backref='comments')

    @property
    def reply_form(self):
        form = CommentForm(parent_id=self.id, discussion_id=self.discussion.id)
        return form

class Discussion(db.Model):
    __tablename__ = 'discussions'
    id = db.Column(db.Integer, primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    circle = db.relationship('Circle', backref='discussions')

    root_comments = db.relationship('Comment', primaryjoin='and_(Comment.discussion_id == Discussion.id, Comment.parent_id == None)')
    

# It needs events
class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    name = db.Column(db.String(80))
    description = db.Column(db.Text)

class EventCircles(db.Model):
    __tablename__ = 'event_circles'
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), primary_key=True)
    # NOTE: could turn this into a circle-component class without altering the database
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'), primary_key=True)
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussions.id'))
    
class Invitation(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.String(80), primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    inviter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    acceptor_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    inviter = db.relationship(User, backref='invitations', primaryjoin=inviter_id == User.id)
    acceptor = db.relationship(User, backref='invitations_accepted', primaryjoin=acceptor_id == User.id)
    circle = db.relationship(Circle, backref='invitations')

    @property
    def url(self):
        return url_for('invitation', id=self.id, _external=True)

    @property
    def inviter_name(self):
        return db.session.query(CircleMembership).filter(db._and(CircleMembership.circle == self.circle, CircleMembership.user == self.inviter)).first().nickname
    
    @property
    def acceptor_name(self):
        return db.session.query(CircleMembership).filter(db._and(CircleMembership.circle == self.circle, CircleMembership.user == self.acceptor)).first().nickname

    def __init__(self, **kwargs):
        self.id = make_invitation_id()
        super(Invitation, self).__init__(**kwargs)

def invitations_for_circle(circle, user=None):
    if not user:
        user = g.user
    return db.session.query(Invitation).filter(db.and_(Invitation.inviter == g.user, Invitation.circle == circle))

def unused_invitations_for_circle(circle, user=None):
    return invitations_for_circle(circle, user).filter(Invitation.acceptor == None)

def make_invitations(circle, count=10):
    # find out how many unused invitations there are
    unused_invitations_count = unused_invitations_for_circle(circle).count() #db.session.query(Invitation).filter(db.and_(Invitation.inviter == g.user, Invitation.circle == circle, Invitation.acceptor == None)).count()

    for index in xrange(count - unused_invitations_count):
        invitation = Invitation(inviter=g.user, circle=circle)
        db.session.add(invitation)


class InviteEmailsForm(Form):
    emails = TextAreaField("List some emails of people you'd like to invite. One per line please")

class JoinCircleForm(Form):
    nickname = TextField('What would you like to be called in this circle?', [validators.Required()])
    
class CreateCircleForm(Form):
    name = TextField('Name your Circle', [validators.Length(min=2, max=80)])
    description = TextAreaField('Describe it')
    # TODO: implement private circles later.  Or maybe they're all private for now?
    
class CommentForm(Form):
    text = TextAreaField('Comment')
    parent_id = HiddenField()#IntegerField(widget=widgets.HiddenInput())
    discussion_id = HiddenField()#IntegerField(widget=widgets.HiddenInput())
    
class LoginForm(Form):
    login = TextField('Login name', [validators.Required()],
        description='This name is only used for logging in to the site.  No one will ever see it.')
    password = PasswordField('Password', [validators.Required()])
    
class AcceptInvitationForm(Form):
    join = FormField(JoinCircleForm)
    credentials = FormField(LoginForm)

@app.before_request
def set_current_user():
    user_id = web_session.get('user_id',None)
    if user_id:
        g.user = User.query.filter_by(id=user_id).first()
    else:
        g.user = None

from flaskext.mail import Message

@app.route("/")
def front():
#    msg = Message("Hello", sender="nickretallack@gmail.com", recipients=["nickretallack@gmail.com"])
#    msg.body = "Testing"
#    msg.html = "<b>Yeah</b>"
#    mail.send(msg)

    your_circles = db.session.query(Circle).join(CircleMembership).filter(CircleMembership.user == g.user)
    return render('front.html', your_circles=your_circles)

@app.route('/circles/<int:id>/invite')
def invite(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    make_invitations(circle)
    db.session.commit()
    invitations = invitations_for_circle(circle).all()
    return render('invite.html', circle=circle, invitations=invitations)

@app.route('/invitation/<string:id>', methods=['GET','POST'])
def invitation(id):
    invitation = get_required(Invitation, id)
    form = JoinCircleForm(request.form)
    if request.method == 'POST' and form.validate():
        # We create an honorary user so you can browse a bit before you create your credentials
        user = User()
        invitation.acceptor = user
        membership = CircleMembership(user=user, circle=invitation.circle, nickname=form.nickname.data)
        
        db.session.add(user)
        db.session.add(membership)
        db.session.commit()
        set_current_user(user)
        return redirect(invitation.circle.url)
    return render('invitation.html', invitation=invitation, form=form)

@app.route('/circles/<int:id>')
def show_circle(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    discussion_form = CommentForm(request.form, discussion_id=5)
    discussions = db.session.query(Discussion).filter_by(circle_id=circle.id).options(db.joinedload(Discussion.comments)).all()
    
    return render('circle.html', circle=circle, discussion_form=discussion_form, discussions=discussions)
    
@app.route('/circles/new', methods=['GET','POST'])
def new_circle():
    circle_form = CreateCircleForm(request.form, prefix='circle')
    membership_form = JoinCircleForm(request.form, prefix='membership')
    #invitation_form = InviteEmailsForm(request.form, prefix='invitations')
    if request.method == 'POST' and circle_form.validate() and membership_form.validate():
        circle = Circle(creator=g.user)
        circle_form.populate_obj(circle)
        db.session.add(circle)

	# create a membership for the creator
	membership = CircleMembership(circle=circle, user=g.user)
        membership_form.populate_obj(membership)
        db.session.add(membership)

        # TODO: create invitations and send emails to all the invited folks

        db.session.commit()
        return redirect(url_for('show_circle', id=circle.id))
    return render('new_circle.html', circle_form=circle_form, membership_form=membership_form) #, invitation_form=invitation_form)

@app.route('/circles/<int:id>/comments', methods=['POST'])
def new_comment(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    form = CommentForm(request.form)
    if request.method == 'POST' and form.validate():
        discussion_id = form.discussion_id.data
        parent_id = form.parent_id.data

        if discussion_id:
            discussion = db.session.query(Discussion).filter_by(id=discussion_id).first()
        else:
            discussion = Discussion(circle=circle)
            db.session.add(discussion)

        comment = Comment(discussion=discussion, parent_id=form.parent_id.data, text=form.text.data, user=g.user)
        db.session.add(comment)
        db.session.commit()

        return redirect(url_for('show_circle',id=circle.id))

def set_current_user(user):
    if user is None:
        web_session['user_id'] = None
    else: 
        web_session['user_id'] = user.id
    


@app.route('/login', methods=['GET','POST'])
def login():
    # Some complex logic here.  If you are already logged in and have credentials,
    # you shouldn't be able to log in again.  But if you don't have credentials yet,
    # your login will associate them with your current account.

    merge_users = False
    if g.user:
        if g.user.credentials:
            abort(404)
        else:
            merge_users = True

    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        action = request.form.get('action',None)
        login = form.login.data
        password = form.password.data
        credentials = db.session.query(PasswordCredentials).filter_by(login=login).first()
        if action == 'login':
            if not credentials:
                form.login.errors.append("This login doesn't exist yet.")
            elif credentials.check_password(password):
                set_current_user(credentials.user)
                # flash successful login
                return redirect(url_for('front'))
            else:
                form.password.errors.append("This password is incorrect for this login")
            
        elif action == 'register':
            if credentials:
                form.login.errors.append("This login already exists.")
            else:
                if merge_users:
                    user = g.user
                else:
                    user = User()
                credentials = PasswordCredentials(user=user, login=login)
                credentials.set_password(password)

                db.session.add(user)
                db.session.add(credentials)
                db.session.commit()
                set_current_user(user)
                return redirect(url_for('front'))
        else:
            return "Something is not right"

    return render('login.html', form=form)

@app.route('/logout')
def logout():
    set_current_user(None)
    return redirect(url_for('front'))

if __name__ == "__main__":
    app.run(debug=True)
