import unittest
import tempfile
import os
import circles.main
import circles
from circles.main import db, app
from circles.main import *

from werkzeug import generate_password_hash

from flaskext.testing import TestCase

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        db.create_all()

        # fixtures
        joe = User()
        cred = PasswordCredentials(user=joe, login='joe')
        cred.set_password('joe')
        circle = Circle(name="Circle of Joe")
        member = Member(circle=circle, user=joe, nickname='Not Joe')
        invitation = Invitation(inviter=member, circle=circle)
        db.session.add_all([joe,cred,circle,member,invitation])
        db.session.commit()

        self.circle = circle
        self.invitation = invitation

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def register(self, *args):
        return self.login(*args, action='register')

    def login(self, login, password, action='login'):
        return self.app.post('/login', data=dict(
            login=login,
            password=password,
            action=action,
        ), follow_redirects=True)

    def logout(self):
        return self.app.get('/logout', follow_redirects=True)

class TestLogins(FlaskTestCase):
    def test_front_page(self):
        rv = self.app.get('/')
        assert 'Circles' in rv.data
        assert 'Create a circle' not in rv.data

    def test_register_logout_login(self):
        rv = self.register('fred','fred')
        assert 'Create a circle' in rv.data
        rv = self.logout()
        assert 'Create a circle' not in rv.data
        

class TestInvitations(FlaskTestCase):
    def test_visiting_your_circle(self):
        self.login('joe','joe')
        rv = self.app.get('/circles/%s' % self.circle.id)
        assert rv.status_code == 200

        rv = self.app.get('/circles/%s/invite' % self.circle.id)
        assert rv.status_code == 200

    def test_inviting_someone(self):
        with app.test_request_context():
            url = self.invitation.url[len('http://localhost'):]

        # Invite should give you access to joe's circle
        rv = self.app.get(url, follow_redirects=True)
        assert self.circle.name in rv.data
        #assert 'form' not in rv.data # not logged in, so no forms

        # See that this invitation is listed on the front page
        rv = self.app.get('/')
        assert 'invited you' in rv.data

        # Try to join the group.  It makes you register
        rv = self.app.get('/circles/%s/join' % self.circle.id, follow_redirects=True)
        assert 'Login or Register' in rv.data
        rv = self.register('bob','bob')
        rv = self.app.get('/circles/%s/join' % self.circle.id, follow_redirects=True)
        assert '<h1>Join' in rv.data
        rv = self.app.post('/circles/%s/join' % self.circle.id, follow_redirects=True, data=dict(nickname='Bob'))
        assert rv.status_code == 200

        # make sure the invitation is cleared away
        rv = self.app.get('/')
        assert 'invited you' not in rv.data
        
if __name__ == '__main__':
    unittest.main()
