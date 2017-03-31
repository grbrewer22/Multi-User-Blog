import os
import re
import random
import hashlib
import hmac
from string import letters

import jinja2
import webapp2
import time
import datetime

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)
error = ""

secret = 'du.uyHJfg94.92^4st-zuJ318&DF9pby0y0'

cookie_separator = '|'
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return "%s%s%s" % (val, cookie_separator, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split(cookie_separator)[0]
    if secure_val == make_secure_val(val):
        return val

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BaseHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    author = db.StringProperty(required=True) # author = db.ReferenceProperty(User) => post.author
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    like_count = db.IntegerProperty(default=0)
    user_like = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

class Comment(db.Model):
    author = db.StringProperty(required=True) # author = db.ReferenceProperty(User) =>
    content = db.TextProperty(required=True)
    postid = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self.__render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self)

class BlogFront(BaseHandler):
    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)

class PostPage(BaseHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

class NewPost(BaseHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        author = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_like = []

        if subject and content:
            p = Post(parent = blog_key(),
                     subject = subject,
                     content = content,
                     author = author) # author = self.user.key()
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                     subject=subject,
                     content=content,
                     error=error)


class EditPost(BaseHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return

            if self.user.name == post.author:
                self.render("edit-post.html", post=post)
            else:
                self.write("Hey! This is not your post to edit!")
        else:
            return self.redirect('/login')


    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            upVal = Post.get_by_id(int(post_id), parent=blog_key())
            if not upVal:
                return self.error(404)
            upVal.subject = subject
            upVal.content = content
            upVal.put()
            self.redirect('/blog/%s' % str(upVal.key().id()))

        else:
                error = "subject and content, please!"
                self.render("edit-post.html",
                    subject=subject,
                    content=content,
                    error=error)

        if "delete" in self.request.POST:
            if not self.user:
                self.redirect('/blog')

            postid = Post.get_by_id(int(post_id), parent=blog_key())
            if not postid:
                return self.error(404)
            self.redirect(
                '/blog/confirmdelete/%s' % str(postid.key().id())
            )

class ConfirmDelete(BaseHandler):

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            query = db.get(key)
            if not query:
                return self.error(404)
            self.render("confirm-delete.html", query=query)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        if "delete-post" in self.request.POST:
            delVal = Post.get_by_id(int(post_id), parent=blog_key())
            if not delVal:
                return self.error(404)
            delVal.delete()
            time.sleep(0.1)
            return self.redirect("/blog")

        if "cancel-delete" in self.request.POST:
            return self.redirect("/blog")

class LikePost(BaseHandler):
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if self.user.name != post.author:
                if self.user.name in post.user_like:
                    self.write("you can only like a post once")
                else:
                    post.user_like.append(self.user.name)
                    post.like_count += 1
                    post.put()
                    time.sleep(0.1)
                    self.redirect("/blog")
            if self.user.name == post.author:
                self.write("you can't like your own post!")

        else:
            self.redirect("/login")


class CommentPostPage(BaseHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                return self.error(404)

            comments = db.GqlQuery(
                "SELECT * FROM Comment WHERE postid =:1", str(post_id)
                )
            self.render(
                "post-comments.html",
                post=post,
                comments=comments
                )
        else:
            self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        if "submit" in self.request.POST:
            content = self.request.get('content')
            author = self.user.name

            if content:
                c = Comment(
                    postid=post_id,
                    content=content,
                    author=author
                    )
                c.put()
                time.sleep(0.1)
                return self.redirect('/blog/commentpost/%s' % post_id)
        if "cancel" in self.request.POST:
            return self.redirect("/blog/%s" % str(post_id))


class EditComment(BaseHandler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if not comment:
                return self.error(404)

            if self.user.name == comment.author:
                self.render("edit-comment.html", comment=comment)
            else:
                self.write("Hey! This is not your comment to edit!")
        else:
            self.redirect("/login")

    def post(self, comment_id):
        if not self.user:
            return self.redirect("/blog")

        content = self.request.get('content')
        commentVal = Comment.get_by_id(int(comment_id))

        if "update" in self.request.POST:
            if content:
                commentVal.content = content
                commentVal.put()
                time.sleep(0.1)
                return self.redirect(
                    "/blog/commentpost/%s" % str(commentVal.postid)
        )

###### Unit 2 HW's
class Rot13(BaseHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Unit3Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/commentpost/([0-9]+)', CommentPostPage),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/confirmdelete/([0-9]+)', ConfirmDelete),
                               ],
                              debug=True)
