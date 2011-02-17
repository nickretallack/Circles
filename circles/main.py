from flask import render_template as render, request,  g, redirect, session as web_session, url_for, abort, json, flash
from werkzeug import generate_password_hash, check_password_hash
from werkzeug.datastructures import MultiDict
from wtforms import *
from uuid import uuid4 
from association import association

from circles import app, db

@app.route("/")
def front():
    your_circles = db.session.query(Circle).join(Member).filter(Member.user == g.user)
    invitations = get_active_invitations()
    
    return render('front.html', your_circles=your_circles, invitations=invitations)

# -------------------------------- HELPERS -----------------------------

def required(result):
    if not result:
        abort(404)
    return result

def get_required(model, id):
    return required(db.session.query(model).filter_by(id=id).first())

# -------------------------------- LOGIN  ------------------------------

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.Date)

class PasswordCredentials(db.Model):
    __tablename__ = 'passwords'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    login = db.Column(db.String(80), unique=True, primary_key=True)
    hashed_password = db.Column(db.String(80))

    user = db.relationship('User', backref='credentials')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

class OpenIDCredentials(db.Model):
    __tablename__ = 'openids'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    openid = db.Column(db.String(80), primary_key=True)

class LoginForm(Form):
    login = TextField('Login name', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])
    next = HiddenField()
    
def set_current_user(user):
    if user is None:
        web_session['user_id'] = None
        # also clear invitations if you log out
        g.invitations = {}
        save_active_invitations()
    else: 
        web_session['user_id'] = user.id
    
@app.before_request
def set_current_user_from_session():
    user_id = web_session.get('user_id',None)
    if user_id:
        g.user = User.query.filter_by(id=user_id).first()
    else:
        g.user = None

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
                flash("You are now registered and logged in as %s.  Don't forget your name and password, since we have no way of reminding you!" % login)
                return redirect(form.next.data)
        else:
            return "Something is not right"

    return render('login.html', form=form)

@app.route('/logout')
def logout():
    set_current_user(None)
    return redirect(url_for('front'))

# -------------------------------- GROUPS ------------------------------

class Circle(db.Model):
    __tablename__ = 'circles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.Text)
    visibility = db.Column(db.String(20))
    gate = db.Column(db.String(20)) # (anyone, chain-of-trust)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    creator = db.relationship('User', backref='circles_created')

    def get_member(user):
        return self.members.filter(Member.user == user).first()

    @property
    def url(self):
        return url_for('show_circle', id=self.id)

# TODO: rename to just Member
class Member(db.Model):
    __tablename__ = 'members'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    nickname = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.Date)

    user = db.relationship('User', backref='members')
    circle = db.relationship(Circle, backref='members')

    @property
    def name(self):
        return self.nickname # I should probably rename this all over to be consistent

    @classmethod
    def find(self, circle, user=None):
        if not user:
            user = g.user
        return db.session.query(Member).filter(
            db.and_(Member.user == g.user, Member.circle == circle)).first()
    
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

class Trust(db.Model):
    __tablename__ = 'trusts'
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'), primary_key=True)
    trusted_member_id = db.Column(db.Integer, db.ForeignKey('members.id'), primary_key=True)
    # NOTE: assert both members are in the same circle

class JoinCircleForm(Form):
    nickname = TextField('What would you like to be called in this circle?', [validators.Required()])
    
class CreateCircleForm(Form):
    name = TextField('Name your Circle', [validators.Length(min=2, max=80)])
    description = TextAreaField('Describe it')
    # TODO: implement other access patterns for circles

def check_access(circle, member_required=False):
    """To see a circle, you must have a member or an invitation"""
    member = db.session.query(Member).filter(db.and_(Member.circle == circle, Member.user == g.user)).first()
    if member:
        return member
    elif member_required:
        abort(404)
    else:
        if str(circle.id) in g.invitations:
            return None
        else:
            abort(404)

@app.route('/circles/<int:id>')
def show_circle(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    you = check_access(circle)
    discussion_form = CommentForm(request.form)
    postings = db.session.query(Posting).filter_by(circle_id=circle.id).order_by(Posting.id.desc()).all()
    
    return render('circle.html', circle=circle, discussion_form=discussion_form, postings=postings, has_membership=you)
    
@app.route('/circles/new', methods=['GET','POST'])
def new_circle():
    circle_form = CreateCircleForm(request.form, prefix='circle')
    member_form = JoinCircleForm(request.form, prefix='member')
    if request.method == 'POST' and circle_form.validate() and member_form.validate():
        circle = Circle(creator=g.user)
        circle_form.populate_obj(circle)
        db.session.add(circle)

	# create a member for the creator
	member = Member(circle=circle, user=g.user)
        member_form.populate_obj(member)
        db.session.add(member)

        db.session.commit()
        return redirect(url_for('show_circle', id=circle.id))
    return render('new_circle.html', circle_form=circle_form, membership_form=member_form)

@app.route('/circles/<int:id>/join', methods=['GET','POST'])
def join_circle(id):
    circle = get_required(Circle, id)
    required(str(circle.id) in g.invitations)

    if not g.user:
        flash("Before you can join a circle, you must be logged in.")
        return redirect(url_for('login'))

    invitations = get_active_invitations_for_circle(circle.id)
    form = JoinCircleForm(request.form)

    if request.method == 'POST' and form.validate():
        nickname = form.nickname.data
	member = Member(circle=circle, user=g.user)
        form.populate_obj(member)
        db.session.add(member)

        for invitation in invitations:
            invitation.acceptor = member

        db.session.commit()

        # delete the temporary invitation
        del g.invitations[str(circle.id)]
        save_active_invitations()

        flash("You're a member now!  Your nickname here is %s." % nickname)
        return redirect(circle.url)

    return render('join_circle.html', circle=circle, form=form, invitations=invitations)

@app.route('/circles/<int:circle_id>/members/<member_id>')
def show_member(circle_id, member_id):
    circle = get_required(Circle, circle_id)
    member = get_required(Member, member_id)
    you = check_access(circle)
    return render('member.html', member=member, you=you)

@app.route('/circles/<int:circle_id>/settings', methods=['GET','POST'])
def member_settings(circle_id):
    circle = get_required(Circle, circle_id)
    you = check_access(circle)
    form = JoinCircleForm(request.form, you)
    if request.method == 'POST' and form.validate():
        nickname = form.nickname.data
        form.populate_obj(you)
        db.session.commit()
        flash("Your nickname is now %s." % nickname)
        return redirect(circle.url)

    return render('member_settings.html', you=you, form=form, circle=circle)

# -------------------------------- INVITATIONS -------------------------

def make_invitation_id():
    return uuid4().hex

class Invitation(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.String(80), primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    inviter_member_id = db.Column(db.Integer, db.ForeignKey('members.id'))
    acceptor_member_id = db.Column(db.Integer, db.ForeignKey('members.id'))
    clicked = db.Column(db.Boolean, default=False, nullable=False)

    circle = db.relationship(Circle, backref='invitations')
    inviter = db.relationship(Member, backref='invitations', primaryjoin= inviter_member_id == Member.id )
    acceptor = db.relationship(Member, backref='invitations_accepted', primaryjoin= acceptor_member_id == Member.id )

    @property
    def url(self):
        return url_for('invitation', id=self.id, _external=True)

    @property
    def inviter_name(self):
        return self.inviter.nickname
    
    @property
    def acceptor_name(self):
        return acceptor.nickname

    def __init__(self, **kwargs):
        self.id = make_invitation_id()
        super(Invitation, self).__init__(**kwargs)

def make_invitations(circle, count=10):
    unused_invitations_count = unused_invitations_for_circle(circle).count()

    for index in xrange(count - unused_invitations_count):
        member = Member.find(circle)
        invitation = Invitation(inviter=member, circle=circle)
        db.session.add(invitation)

def invitations_for_circle(circle, user=None):
    if not user:
        user = g.user
    return db.session.query(Invitation).filter(db.and_(Invitation.inviter == g.user, Invitation.circle == circle))

def unused_invitations_for_circle(circle, user=None):
    return invitations_for_circle(circle, user).filter(Invitation.acceptor == None)

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

def clicked_invitation(invitation):
    invitation.clicked = True
    circle_id = str(invitation.circle_id)
    if circle_id not in g.invitations:
        g.invitations[circle_id] = []
    g.invitations[circle_id].append(invitation.id)
    save_active_invitations()

def invalidate_self_invitations(user):
    # you may have just accepted your own invitation
    for invitation_set in get_active_invitations():
        for invitation in invitation_set['invitations']:
            if invitation.inviter.user == user:
                g.invitations[str(invitation.circle_id)].remove(invitation.id)
                flash("Oops!  You opened one of your own invitations.")
    save_active_invitations()

    # This could also be used to establish trust with people who've
    # invited you to circles you're already a member of

def save_active_invitations():
    web_session['invitations'] = json.dumps(g.invitations)
    
@app.before_request
def check_invitations():
    g.invitations = json.loads(web_session.get('invitations','{}'))

@app.route('/circles/<int:id>/invite')
def invite(id):
    circle = required(db.session.query(Circle).filter_by(id=id).first())
    check_access(circle, member_required=True)
    make_invitations(circle)
    db.session.commit()
    invitations = invitations_for_circle(circle).all()
    return render('invite.html', circle=circle, invitations=invitations)

@app.route('/invitation/<string:id>', methods=['GET','POST'])
def invitation(id):
    """ If you have an invitation, that grants you a key to read anything in the circle,
    but you can't write anything until you create your credentials.
    I'd love to let you write stuff, but it'd be complicated to merge things if you
    forgot to log in and ended up with two members to the same circle."""
    invitation = get_required(Invitation, id)
    if g.user == invitation.inviter.user:
        flash("You can't send an invitation to yourself.")
        return redirect(url_for('front'))
    if invitation.acceptor_member_id:
        flash("This invitation has already been used.")
        return redirect(url_for('front'))
    clicked_invitation(invitation)
    db.session.commit()
    return redirect(invitation.circle.url)

# -------------------------------- DISCUSSIONS -------------------------

class Discussion(db.Model):
    __tablename__ = 'discussions'
    id = db.Column(db.Integer, primary_key=True)

    root_comments = db.relationship('Comment', primaryjoin='and_(Comment.discussion_id == Discussion.id, Comment.parent_id == None)')

class PrivateDiscussion(db.Model):
    __tablename__ = 'private_discussion'
    id = db.Column(db.Integer, primary_key=True)
    member1_id = db.Column(db.Integer, db.ForeignKey('members.id'))
    member2_id = db.Column(db.Integer, db.ForeignKey('members.id'))
    discussion_id = db.Column(None, db.ForeignKey('discussions.id'))

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'))
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussions.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=True) # (can be null) - for threading
    text = db.Column(db.Text)
    date = db.Column(db.DateTime) # (for ordering)

    member = db.relationship('Member', backref='comments')
    discussion = db.relationship('Discussion', backref='comments')
    parent = db.relationship('Comment', backref='children', remote_side=[id])

    @property
    def nickname(self):
        return self.member.nickname

    @property
    def reply_form(self):
        return CommentForm(parent_id=self.id)

class CommentForm(Form):
    text = TextAreaField('Comment')
    parent_id = HiddenField()
    
def parse_integer(integer):
    if not integer:
        return None
    else:
        return int(integer)

#@app.route('/members/<int:member_id>/comments', methods=['POST'])
#def new_member_comment(member_id):
#    member = get_required(Member, member_id)
#    you = check_access(circle, True)
#    circle = member.circle
#    form = CommentForm(request.form)
#    if request.method == 'POST' and form.validate():
#        discussion_id = parse_integer(form.discussion_id.data)
#        parent_id = parse_integer(form.parent_id.data)
#        text = form.text.data

@app.route('/circles/<int:circle_id>/postings/', methods=['POST'])
def new_posting(circle_id):
    circle = get_required(Circle, circle_id)
    you = check_access(circle, True)
    form = CommentForm(request.form)
    if request.method == 'POST' and form.validate():
        posting = Posting(circle=circle)
        no_media = NoMedia()
        no_media.postings.append(posting)
        db.session.add(posting)
        db.session.add(no_media)
        post_comment(form, posting.discussion, you)
        db.session.commit()
    
    return redirect(url_for('show_circle',id=circle.id))

def post_comment(form, discussion, you):
    parent_id = parse_integer(form.parent_id.data)
    text = form.text.data
    comment = Comment(discussion=discussion, parent_id=parent_id, text=text, member=you)
    db.session.add(comment)
    return comment

@app.route('/postings/<int:posting_id>/comments', methods=['POST'])
def reply_to_posting(posting_id):
    posting = get_required(Posting, posting_id)
    circle = posting.circle
    you = check_access(circle, True)
    form = CommentForm(request.form)
    if request.method == 'POST' and form.validate():
        discussion = posting.discussion
        post_comment(form, discussion, you)
        db.session.commit()

    return redirect(url_for('show_circle',id=circle.id))

# -------------------------------- MEDIA -------------------------------

class Posting(db.Model):
    __tablename__ = 'posting'
    id = db.Column(db.Integer, primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circles.id'))
    creator_id = db.Column(db.Integer, db.ForeignKey('members.id'))
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussions.id'))

    # polymorphism
    association_id = db.Column(db.Integer, db.ForeignKey('posting_associations.id'))
    type = db.Column(db.String(50))

    feedworthy = db.Column(db.Boolean, default=True)

    circle = db.relationship(Circle, backref=db.backref('postings', order_by=id.desc()))
    discussion = db.relationship('Discussion', backref='posting', uselist=False)

    def __init__(self, *args, **kwargs):
        super(Posting, self).__init__(*args, **kwargs)
        self.discussion = Discussion()

postable = association(Posting, 'media')

class Photo(db.Model):
    __tablename__ = 'photos'
    id = db.Column(db.Integer, primary_key=True)
    posting_association_id = db.Column(db.Integer, db.ForeignKey('posting_associations.id'))

    hash = db.Column(db.String(80))
    filename = db.Column(db.String(80)) # - sanitized by werkzeug.  Place photos in <hash>/filename
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id')) # -- handled by a relationship?  *shrug*  nah we can special case this
    uploaded_at = db.Column(db.Date)

postable(Photo, 'postings')

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    posting_association_id = db.Column(db.Integer, db.ForeignKey('posting_associations.id'))

    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    name = db.Column(db.String(80))
    description = db.Column(db.Text)

postable(Event, 'postings')

class NoMedia(db.Model):
    """Used for postings that have no associated media.
    It'd be nice if I could get rid of this placeholder table."""
    __tablename__ = "no_media"
    id = db.Column(db.Integer, primary_key=True)
    posting_association_id = db.Column(db.Integer, db.ForeignKey('posting_associations.id'))

postable(NoMedia, 'postings')

class Location(db.Model):
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(80)) # (string for google maps)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

# not used yet
class PhotoRelationship(db.Model): # - tags users in photos
    __tablename__ = 'photo_relationships'
    photo_id = db.Column(db.Integer, db.ForeignKey('photos.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    relationship = db.Column(db.String(20), primary_key=True) # (uploaded, drew, for, in, from)

# -------------------------------- END  ------------------------------
