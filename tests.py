import unittest
import tempfile
import os
import circles.main
import circles
from circles.main import db

from fixture import DataSet, SQLAlchemyFixture, NamedDataStyle
from werkzeug import generate_password_hash


class PasswordCredentialsData(DataSet):
    class joe_cred:
        login='joe'
        password=generate_password_hash('joe')
    class bob_cred:
        login='bob'
        password=generate_password_hash('bob')

class UserData(DataSet):
    class joe:
        credentials = [PasswordCredentialsData.joe_cred]
    class bob:
        credentials = [PasswordCredentialsData.bob_cred]

class CircleData(DataSet):
    class joe_circle:
        id = 1
        name = "Joe's Circle"
        creator = UserData.joe

class MemberData(DataSet):
    class joe_member:
        id = 1
        circle = CircleData.joe_circle
        user = UserData.joe
        nickname = "Not Joe"

class InvitationData(DataSet):
    class joe_invitation:
        id = 1
        circle = CircleData.joe_circle
        inviter = MemberData.joe_member

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        circles.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
        self.app = circles.app.test_client()
        db.create_all()
        self.fixtures = SQLAlchemyFixture(env=circles.main, 
            style=NamedDataStyle(), engine=db.engine)
        data = self.fixtures.data(UserData, PasswordCredentialsData)
        data.setup()

    def tearDown(self):
        db.session.remove()
        self.fixtures.dispose()
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
#    def setUp(self):
#        super(TestInvitations, self).setUp()
#
#        # make a user for existing user tests
#        self.register('fred','fred')
#        self.logout()
#
#        # make a user with a circle and stay logged in as them
#        self.register('joe','joe')
#        rv = self.app.post('/circles/new', data={
#            'circle-name':"joe's circle",
#            'circle-description':"Circle of Joe",
#            'member-nickname':'Jose',
#        }, follow_redirects=True)
    
    def test_invite_new_user(self):
        self.login('joe','joe')
        import pdb; pdb.set_trace()
        rv = self.app.get('/circles/%s' % CircleData.joe_circle.id)
        print rv.data
        assert rv.status_code == 200
#        rv = self.app.get('/cicles/1/invite')
#        print rv.data
#        invitation = db.session.query(circles.main.Invitation).first()
#        self.logout()
#
#        # visiting a url should give us access to the page
#        rv = self.app.get(invitation.url)
#        assert 'Circle of Joe' in rv.data
        
        



if __name__ == '__main__':
    unittest.main()
