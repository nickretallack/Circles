from flask import Flask, render_template as render, request,  g, redirect, session as web_session, url_for, abort, json, flash
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

    def get_membership(user):
        return self.memberships.filter(CircleMembership.user == user).first()

    @property
    def url(self):
        return url_for('show_circle', id=self.id)

# TODO: rename to just Member
class CircleMembership(db.Model):
    __tablename__ = 'user_circles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    nickname = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Date)

    user = db.relationship(User, backref='memberships')
    circle = db.relationship(Circle, backref='memberships')

    @classmethod
    def find(self, circle, user=None):
        if not user:
            user = g.user
        return db.session.query(CircleMembership).filter(
            CircleMembership.user == g.user, CircleMembership.circle == circle)
    
    @property
    def private_discussions_with_you(self):
        you = self.find(g.user, self.circle)
        return private_discussions_with(you)

    def private_discussions_with(self, member):
        return db.session.query(PrivateDiscussion).filter(db.or_(
            db.and_(PrivateDiscussion.member1 == self, PrivateDiscussion.member2 == member),
            db.and_(PrivateDiscussion.member1 == member, PrivateDiscussion.member2 == self)))

    @property
    def url(self):
        return url_for('show_member', circle_id=self.circle_id, member_id=self.id)

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

class PrivateDiscussion(db.Model):
    __tablename__ = 'private_discussion'
    id = db.Column(db.Integer, primary_key=True)
    member1_id = db.Column(db.Integer, db.ForeignKey('user_circles.id'))
    member2_id = db.Column(db.Integer, db.ForeignKey('user_circles.id'))
    #discussion_id = db.Column(db.

class PhotoCircle(db.Model): # -- determines whether the photo is visible to a given circle
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
    def membership(self):
        return db.session.query(CircleMembership).filter(db.and_(CircleMembership.user == self.user, CircleMembership.circle == self.discussion.circle)).first()

    @property
    def nickname(self):
        return self.membership.nickname

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
    clicked = db.Column(db.Boolean, default=False, nullable=False)

    inviter = db.relationship(User, backref='invitations', primaryjoin=inviter_id == User.id)
    acceptor = db.relationship(User, backref='invitations_accepted', primaryjoin=acceptor_id == User.id)
    circle = db.relationship(Circle, backref='invitations')

    @property
    def url(self):
        return url_for('invitation', id=self.id, _external=True)

    @property
    def inviter_name(self):
        return db.session.query(CircleMembership).filter(db.and_(CircleMembership.circle == self.circle, CircleMembership.user == self.inviter)).first().nickname
    
    @property
    def acceptor_name(self):
        return db.session.query(CircleMembership).filter(db.and_(CircleMembership.circle == self.circle, CircleMembership.user == self.acceptor)).first().nickname

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
    parent_id = HiddenField() #IntegerField(widget=widgets.HiddenInput())
    discussion_id = HiddenField() #IntegerField(widget=widgets.HiddenInput())
    
class LoginForm(Form):
    login = TextField('Login name', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])
    next = HiddenField()
    
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

@app.before_request
def check_invitations():
    g.invitations = json.loads(web_session.get('invitations','{}'))


from flaskext.mail import Message

@app.route("/")
def front():
#    msg = Message("Hello", sender="nickretallack@gmail.com", recipients=["nickretallack@gmail.com"])
#    msg.body = "Testing"
#    msg.html = "<b>Yeah</b>"
#    mail.send(msg)

    your_circles = db.session.query(Circle).join(CircleMembership).filter(CircleMembership.user == g.user)
    invitations = get_active_invitations()
    
    return render('front.html', your_circles=your_circles, invitations=invitations)

@app.route('/circles/<int:id>/invite')
def invite(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    check_access(circle, membership_required=True)
    make_invitations(circle)
    db.session.commit()
    invitations = invitations_for_circle(circle).all()
    return render('invite.html', circle=circle, invitations=invitations)

def clicked_invitation(invitation):
    invitation.clicked = True
    circle_id = str(invitation.circle_id)
    if circle_id not in g.invitations:
        g.invitations[circle_id] = []
    g.invitations[circle_id].append(invitation.id)
    save_active_invitations()

@app.route('/invitation/<string:id>', methods=['GET','POST'])
def invitation(id):
    """ If you have an invitation, that grants you a key to read anything in the group,
    but you can't write anything until you create your credentials.
    I'd love to let you write stuff, but it'd be complicated to merge things if you
    forgot to log in and ended up with two memberships to the same group."""
    invitation = get_required(Invitation, id)
    if g.user == invitation.inviter:
        flash("You can't send an invitation to yourself")
        return redirect(url_for('front'))
    if invitation.acceptor_id:
        flash("This invitation has already been used")
        return redirect(url_for('front'))
    clicked_invitation(invitation)
    db.session.commit()
    return redirect(invitation.circle.url)

def check_access(circle, membership_required=False):
    """To see a circle, you must have a membership or an invitation"""
    membership = db.session.query(CircleMembership).filter(db.and_(CircleMembership.circle == circle, CircleMembership.user == g.user)).first()
    if membership:
        return True
    elif membership_required:
        abort(404)
    else:
        if str(circle.id) in g.invitations:
            return False
        else:
            abort(404)

@app.route('/circles/<int:id>')
def show_circle(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    has_membership = check_access(circle)
    discussion_form = CommentForm(request.form)
    discussions = db.session.query(Discussion).filter_by(circle_id=circle.id).options(db.joinedload(Discussion.comments)).all()
    
    return render('circle.html', circle=circle, discussion_form=discussion_form, discussions=discussions, has_membership=has_membership)
    
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

def get_active_invitations():
    results = []
    for circle_id, invitation_ids in g.invitations.iteritems():
        circle = Circle.query.get(circle_id)
        invitations = get_active_invitations_for_circle(circle_id)
        results.append({'circle':circle, 'invitations':invitations})
    return results 


def get_active_invitations_for_circle(circle_id):
    circle_id = str(circle_id)
    invitation_ids = g.invitations.get(circle_id, None)
    if invitation_ids:
        return db.session.query(Invitation).filter(Invitation.id.in_(invitation_ids))
    else:
        return []

@app.route('/circles/<int:id>/join', methods=['GET','POST'])
def join_circle(id):
    circle = get_required(Circle, id)
    required(str(circle.id) in g.invitations)

    if not g.user:
        flash("Before you can join a circle, you must be logged in")
        return redirect(url_for('login'))

    invitations = get_active_invitations_for_circle(circle.id)
    form = JoinCircleForm(request.form)

    if request.method == 'POST' and form.validate():
        nickname = form.nickname.data
	membership = CircleMembership(circle=circle, user=g.user)
        form.populate_obj(membership)
        db.session.add(membership)
        db.session.commit()

        # delete the temporary invitation
        g.invitations[str(circle.id)] = []
        save_active_invitations()

        flash("You're a member now!  Your nickname here is %s" % nickname)
        return redirect(circle.url)

    return render('join_circle.html', circle=circle, form=form, invitations=invitations)

def save_active_invitations():
    web_session['invitations'] = json.dumps(g.invitations)
    

def parse_integer(integer):
    if not integer:
        return None
    else:
        return int(integer)

# TODO: make a generic discussion reply thing
@app.route('/discussion/<int:discussion_id>', methods=['POST'])
def discuss(discussion_id):
    discussion = get_required(Discussion, discussion_id)
    form = CommentForm(request.form)
    parent_id = parse_integer(form.parent_id.data)
    text = form.text.data
    comment = Comment(discussion=discussion, parent_id=parent_id, text=text, user=g.user)
    db.session.add(comment)
    db.session.commit()
    if request.referer:
        return redirect(request.referrer)
    else:
        return 'OK' # Could redirect somewhere smart I suppose
    
    


@app.route('/circles/<int:id>/comments', methods=['POST'])
def new_comment(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    check_access(circle)
    form = CommentForm(request.form)
    if request.method == 'POST' and form.validate():
        discussion_id = parse_integer(form.discussion_id.data)
        parent_id = parse_integer(form.parent_id.data)
        text = form.text.data

        if discussion_id:
            discussion = db.session.query(Discussion).filter_by(id=discussion_id).first()
        else:
            discussion = Discussion(circle=circle)
            db.session.add(discussion)

        comment = Comment(discussion=discussion, parent_id=parent_id, text=text, user=g.user)
        db.session.add(comment)
        db.session.commit()

    return redirect(url_for('show_circle',id=circle.id))

def set_current_user(user):
    if user is None:
        web_session['user_id'] = None
        # also clear invitations if you log out
        g.invitations = {}
        save_active_invitations()
    else: 
        web_session['user_id'] = user.id
    
def invalidate_self_invitations(user):
    # you may have just accepted your own invitation
    for invitation_set in get_active_invitations():
        for invitation in invitation_set['invitations']:
            if invitation.inviter == user:
                g.invitations[str(invitation.circle_id)].remove(invitation.id)
                flash("Oops!  You opened one of your own invitations")
    save_active_invitations()

    # This could also be used to establish trust with people who've
    # invited you to circles you're already a member of
    

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        referrer = request.referrer or url_for('front')
    else:
        referrer = url_for('front')

    form = LoginForm(request.form, next=referrer)
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
                invalidate_self_invitations(credentials.user)
                # flash successful login
                return redirect(form.next.data)
            else:
                form.password.errors.append("This password is incorrect for this login")
            
        elif action == 'register':
            if credentials:
                form.login.errors.append("This login already exists.")
            else:
                user = User()
                credentials = PasswordCredentials(user=user, login=login)
                credentials.set_password(password)

                db.session.add(user)
                db.session.add(credentials)
                db.session.commit()
                set_current_user(user)
                return redirect(form.next.data)
        else:
            return "Something is not right"

    return render('login.html', form=form)

@app.route('/logout')
def logout():
    set_current_user(None)
    return redirect(url_for('front'))

@app.route('/circles/<int:circle_id>/members/<member_id>')
def show_member(circle_id, member_id):
    circle = get_required(Circle, circle_id)
    member = get_required(CircleMembership, member_id)
    check_access(circle)
    return render('member.html', member=member)

@app.route('/members/<int:member_id>/comments', methods=['POST'])
def new_private_discussion(member_id):
    member = get_required(CircleMembership, member_id)
    circle = member.circle
    you = required(CircleMembership.find(circle))
    form = CommentForm(request.form)
    if request.method == 'POST' and form.validate():
        discussion_id = parse_integer(form.discussion_id.data)
        parent_id = parse_integer(form.parent_id.data)
        text = form.text.data



if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
