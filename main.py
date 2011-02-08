from flask import Flask, render_template as render, request,  g, redirect, session as web_session, url_for
from flaskext.sqlalchemy import SQLAlchemy
from werkzeug import generate_password_hash, check_password_hash
from werkzeug.datastructures import MultiDict
from wtforms import *

def required(result):
    if not result:
        abort(404)
    return result

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://nick@localhost/circles'
db = SQLAlchemy(app)


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
    
class JoinCircleForm(Form):
    nickname = TextField('What would you like to be called in this circle?')
    
class CreateCircleForm(Form):
    name = TextField('Name your Circle', [validators.Length(min=2, max=80)])
    description = TextAreaField('Describe it')
    # TODO: implement private circles later.  Or maybe they're all private for now?
    
class CommentForm(Form):
    text = TextAreaField('Comment')
    parent_id = HiddenField()#IntegerField(widget=widgets.HiddenInput())
    discussion_id = HiddenField()#IntegerField(widget=widgets.HiddenInput())
    
@app.before_request
def set_current_user():
    user_id = web_session.get('current_user_id',None)
    if user_id:
        g.user = User.query.filter_by(id=user_id).first()
    else:
        g.user = db.session.query(User).filter_by(id=2).first() #None #AnonymousUser()

@app.route("/")
def front():
    your_circles = db.session.query(Circle).join(CircleMembership).filter(CircleMembership.user == g.user)
    return render('front.html', your_circles=your_circles)

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
    if request.method == 'POST' and circle_form.validate() and membership_form.validate():
        circle = Circle(creator=g.user)
        circle_form.populate_obj(circle)
        db.session.add(circle)

	# create a membership for the creator
	membership = CircleMembership(circle=circle, user=g.user)
        membership_form.populate_obj(membership)
        db.session.add(membership)

        db.session.commit()
        return redirect(url_for('show_circle', id=circle.id))

    return render('new_circle.html', circle_form=circle_form, membership_form=membership_form)

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



if __name__ == "__main__":
    app.run(debug=True)
