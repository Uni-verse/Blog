import os
import re
import hmac
import hashlib
import random
from string import letters
import webapp2
import jinja2
import json
import cgi

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                        autoescape = True)

secret = '234.sa#fsd90234*&^HK,jkjhsdf&_jklasfd'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
    
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
    
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
    
class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
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
        if self.user:   
            self.redirect('/blog')
        else:
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
        
        
class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else: 
            u = User.register(self.username, self.password, self.email)
            u.put()
            
            self.login(u)
            self.redirect('/welcome')
            

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html', error='')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/login')
        
                      
class Blog_Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    
    @classmethod
    def by_author(cls, author):
        u = Blog_Post.all().filter('author =', author).get()
        return u
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog_post.html", p=self)
    
    def by_id(cls, uid):
        return Blog_Post.get_by_id(uid)
    
    def getlikes(cls, postid):
        counter = 0
        q = db.Query(Likes)
        q.filter('post_id =', postid)
        results = q.fetch(limit=50)
        for row in results:
            counter += 1
            
        return counter
        
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
    
    
class Likes(db.Model):
    user = db.StringProperty(required = True)
    post_id = db.TextProperty(required = True)
    
    @classmethod
    def by_name(cls, name):
        u = Likes.all().filter('post_id =', name).get()
        return u
    
    @classmethod
    def add(cls, user, postid):
        return Likes(user = user, post_id = postid)
    
    @classmethod
    def by_id(cls, uid):
        return Likes.get_by_id(uid)
    
    
class Welcome(BaseHandler):
    def get(self):
        if self.user:
            loggedin = True
            self.render('welcome.html', username = self.user.name, loggedin=loggedin)
        else:
            self.redirect('/login')
            
            
class ErrPage(BaseHandler):
    def get(self):
        if self.user:
            loggedin = True
            u = self.user.name
        if self.request.get('liked'):
            self.redirect('/blog')
        elif self.request.get('np'):
            self.redirect('/blog')
        elif self.request.get('msg'):
            msg = self.request.get("msg")
            self.render("err_page.html", msg=msg, loggedin=loggedin, username=u)
        
#class GetLike(BaseHandler):
#    def post(self):
#        counter = 0
#        postid = data["postid"]
#        results = Likes.by_name(int(postid))
#        for x in results:
#            counter = counter + 1
#        
#        self.response.write(json.dumps({"message": message}))
#        output = counter

        
class AjaxHandler(BaseHandler):
    def get(self):
        pass

    def post(self):
        data = json.loads(self.request.body)
        postid = data["postid"]

        message = "success"

        self.response.write(json.dumps({"message": message}))
        
        
class Blog(BaseHandler):
    def get(self):
        if self.user:
            loggedin = True
#        count = db.GqlQuery("Select user FROM Likes WHERE post_id="+str(postid)+"")
#        results = self.count.fetch(limit=1000)
#        for x in results:
#            self.counter = self.counter + 1
#        for c in count:
#            self.counter += 1
        posts = db.GqlQuery("Select * FROM Blog_Post ORDER BY created DESC LIMIT 10")
        self.render("blog.html", posts=posts, page_title="FMQ Blog", loggedin=loggedin)
        
    def post(self):
        if self.user:
            loggedin = True
            
        if self.request.get('addlike') and self.request.get('postid') and self.request.get('author'):
            author = self.request.get("author")
            postid = self.request.get("postid")
            bp = Blog_Post.get_by_id(int(postid))
            if bp.author is not self.user.name:
                q = Likes.add(author, postid)
                q.put()
                posts = db.GqlQuery("Select * FROM Blog_Post ORDER BY created DESC LIMIT 10")
                self.redirect('/err?liked=%s' % bp.author)
#                self.render("blog.html", posts = posts, page_title = "FMQ Blog", loggedin = loggedin)
        else: 
            self.redirect('/blog')


#    def post(self):
#        if self.request.get('id') and self.request.get('author') and self.request.get('addlike'):
#            
        
#class ErrPage(BaseHandler):
#    def get(self):
#        msg = self.request.get("msg")
#        self.render("err_page.html", msg=msg)
        
class DeletePost(BaseHandler):
    def get(self):
        self.redirect("/blog")
        
    def post(self):
        id_to_del = self.request.get("delete")
        q = db.GqlQuery("Select * FROM Blog_Post WHERE id="+id_to_del+" LIMIT 1")
        db.delete(q)
        msg = "You have deleted the post."
        self.render("delete_post.html", msg=msg)
        
        
class PostPage(BaseHandler):
    def get(self, post_id):
        if self.user:
            loggedin = True
            u = Blog_Post.get_by_id(int(post_id))
            key = db.Key.from_path('Blog_Post', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
            elif not u:
                error = "You must be owner of the this post to edit."
                u = ""
                self.render("permalink.html", post=post, error=error, loggedin=loggedin)
            else:
                self.render("permalink.html", post=post, username=u, loggedin=loggedin)
        else: 
            self.redirect('/login')
            
    def post(self, request):
        if self.user:
            loggedin = True
            idTodel = self.request.get('erase')
            p = Blog_Post.get_by_id(int(idTodel))
#            key = db.Key.from_path('Blog_Post', int(idTodel))
#            post = db.get(key)
            if p.author == self.user.name:
                p.delete()
                msg = "Post successfully deleted."
                self.redirect('/err?msg=%s' % str(msg))
            else:
                msg = "You must be the author to edit."
                self.redirect('/err?msg=%s' % str(msg))
                              
        
class NewPost(BaseHandler): 
    def get(self):
        if self.user:
            loggedin = True
            self.render("new_post.html", page_title="New Post", loggedin=loggedin, username=self.user.name)
        else:
            self.redirect('/login')
        
        
    def post(self):
        if self.user:
            loggedin = True
            
        subject = self.request.get("subject")
        content = self.request.get("content")
        author = self.request.get("author")
        
        if subject and content:
            bp = Blog_Post(subject = subject, content = content, author = author)
            bp.put()
            self.redirect('/err?np=%s' % str(bp.key().id()))
        else:
            error = "Please fill both fields."
            self.render("new_post.html", subject=subject, content=content, page_title="New Post", error=error, loggedin=loggedin, username=self.user.name)
        
#class Welcome(BaseHandler):
#    def get(self):
#        username = self.request.get('username')
#        if valid_username(username):
#            self.render('welcome.html', username = username)
#        else:
#            self.redirect('/signup')
            
app = webapp2.WSGIApplication([('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/?', Blog),
                               ('/blog/del', DeletePost),
                               ('/ajax/getlike', AjaxHandler),
                               ('/err', ErrPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage)
                            ])