import os
import re
import time
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
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

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

#Signup Handler
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
        
#Register handler extends Signup       
class Register(Signup):
    #Overwritten Func
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else: 
            u = User.register(self.username,
                              self.password, self.email)
            u.put()
            
            self.login(u)
            self.redirect('/welcome')
         
        
#Login Handler
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

            
#Logout Handler
class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/login')
        
#Likes DB  
class Likes(db.Model):
    user = db.StringProperty(required = True)
    post_id = db.StringProperty(required = True)
    
    @classmethod
    def check(cls, user, postid):
        #Check if specific user is tagged with this post_id
        rows = 0
        q = db.GqlQuery("Select * FROM Likes WHERE "
                        "post_id='"+postid+"' AND user='"+user+"'")
        #get results and check amount of rows
#        if len(q) is 0:
#            return True
#        else: 
#            return False
        for r in q:
            rows += 1
        if rows == 0:
            return True
        else:
            return False

        
# Blog Comments DB        
class Comment(db.Model):
    author = db.StringProperty(required = True)
    post_id = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    likes = db.IntegerProperty()
    
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    
    @classmethod
    def getcomments(cls, post):
        comments = db.GqlQuery("Select * FROM Comment "
                               "WHERE post_id='"+str(post.key().id())+
                               "' ORDER BY created DESC")
        return comments
        
    def render(self):
#        comments = db.GqlQuery("Select * FROM Comment "
#                               "WHERE post_id='"+str(pid.key().id())+
#                               "' ORDER BY created DESC")
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment_post.html", c=self)
    
    
# Blog_Post DB   
class Blog_Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    likes = db.IntegerProperty()
    
    @classmethod
    def by_author(cls, author):
        u = Blog_Post.all().filter('author =', author).get()
        return u
    
    def render_comments(self, c):
        return render_str("comment_post.html", c=c)
    
    def render(self):
        c = db.GqlQuery("Select * FROM Comment "
                        "WHERE post_id='"+str(self.key().id())+
                        "' ORDER BY created DESC")
        if c is not None:
            self.comments = c
        
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog_post.html", p=self)
    
    #Render edit_post.html
    def render_edit(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("edit_post.html", p=self)
    
    @classmethod
    def by_id(cls, uid):
        return Blog_Post.get_by_id(uid)
    
    @classmethod
    def addlike(cls, user, postid):
        #Check Likes database if user is tagged with post_id
        if Likes.check(user, postid):
            p = Blog_Post.get_by_id(int(postid))
            if user != p.author:
                p.likes += 1
                p.put()
                nl = Likes(user = user, post_id = postid)
                nl.put()
            else:
                return
        
#User DB Class       
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
    
    
class Welcome(BaseHandler):
    def get(self):
        if self.user:
            loggedin = True
            self.render('welcome.html',
                        username = self.user.name,
                        loggedin=loggedin)
        else:
            self.redirect('/login')
            
            
#Class used for POST->REDIRECT           
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
            self.render("err_page.html", msg = msg,
                        loggedin = loggedin, username = u)
        
        
#Handler for /blog page   
class Blog(BaseHandler):
    def get(self):
#        q = Comment(author = "sergio", post_id="32523453452345",
#                    content="init comment", likes = 0)
#        q.put()
        posts = db.GqlQuery("Select * FROM Blog_Post ORDER "
                            "BY created DESC LIMIT 10")
        if self.user:
            loggedin = True
            self.render("blog.html", posts = posts,
                        page_title = "FMQ Blog",
                        loggedin = loggedin)
        else:
            self.render("blog.html", posts = posts,
                        page_title = "FMQ Blog")
        
    def post(self):
        posts = db.GqlQuery("Select * FROM Blog_Post ORDER "
                            "BY created DESC LIMIT 10")
        loggedin = False
        if self.user:
            loggedin = True
            # if addlike form is submitted...
            if self.request.get('addlike'):
                postid = self.request.get("addlike")
                bp = Blog_Post.get_by_id(int(postid))
                if bp != None:
                    # if author of post is not current user then addlike
                    if bp.author != self.user.name:
                        Blog_Post.addlike(self.user.name, postid)
                        time.sleep(0.1)
                        self.redirect('/err?liked=%s' % str(postid))
                    else:
                        posts = db.GqlQuery("Select * FROM Blog_Post ORDER BY "
                                            "created DESC LIMIT 10")
                        self.render("blog.html", posts = posts,
                                    page_title = "FMQ Blog",
                                    loggedin = loggedin)
                        
                else:
                    self.render("blog.html", posts = posts,
                                    page_title = "FMQ Blog",
                                    loggedin = loggedin)
                    
            else:
                posts = db.GqlQuery("Select * FROM Blog_Post ORDER BY "
                                    "created DESC LIMIT 10")
                self.render("blog.html", posts = posts,
                            page_title = "FMQ Blog",
                            loggedin = loggedin)
        else:
            self.redirect('/login')
            
    
# Permalink.html Handler /blog/[0-9]        
class PostPage(BaseHandler):
    def get(self, post_id):
        if self.user:
            loggedin = True
            p = Blog_Post.get_by_id(int(post_id))
            # if post author is current user, take to edit page
            if p.author == self.user.name:
                key = db.Key.from_path('Blog_Post', int(post_id))
                post = db.get(key)
                if not post:
                    self.error(404)
                    return
                elif not p:
                    error = "You must be owner of the this post to edit."
                    p = ""
                    self.render("permalink.html", post = post,
                                error = error, loggedin = loggedin,
                                page_title = "Edit Post")
                else:
                    self.render("permalink.html", post = post,
                                username = p, loggedin = loggedin,
                                page_title = "Edit Post")
            else:
                msg = "You must be the author to edit."
                self.redirect('/err?msg=%s' % str(msg))
        else: 
            self.redirect('/login')
                
    def post(self, request):
        if self.user:
            loggedin = True
            # if Delete button was press on post edit page
            if self.request.get('erase'):
                idTodel = self.request.get('erase')
                p = Blog_Post.get_by_id(int(idTodel))
                if p is not None:
                    if p.author == self.user.name:
                        p.delete()
                        msg = "Post successfully deleted."
                        self.redirect('/err?msg=%s' % str(msg))
                    else:
                        msg = "You must be the author to edit."
                        self.redirect('/err?msg=%s' % str(msg))
        else:
            self.redirect('/login')
            
            
# /blog/editcomment handler
class EditComment(BaseHandler):
    def get(self, postid):
        if self.user:
            loggedin = True
            post = Comment.get_by_id(int(postid))
            postid = int(postid)
            if self.user.name == post.author:
                self.render("edit_comment.html",
                           page_title = "Edit Comment",
                           loggedin = loggedin,
                           p = post,
                           username = self.user.name)
            else:
                msg = "You must be the author to edit."
                self.redirect('/err?msg=%s' % str(msg))
        else:
            self.redirect('/login')
    
    def post(self, postid):
        if self.user:
            if self.request.get('edit'):
                cid = self.request.get('edit')
                post = Comment.get_by_id(int(cid))
                if self.request.get('content') == "":
                    self.render("edit_comment.html",
                           page_title = "Edit Comment",
                           p = post,
                           username = self.user.name)
                
                else:
                    body = self.request.get('content')
                    post.content = body
                    if self.user.name == post.author:
                        post.put()
                        msg = "Your post has been edited."
                        self.redirect('/err?msg=%s' % msg)
                    else:
                        redirect('/blog')

        else:
            self.redirect('/login')
                
# /blog/likecomment handler
class LikeComment(BaseHandler):
    def get(self):
        self.redirect('/login')
    
    def post(self):
        pass
    
    
# /blog/comment/([0-9]+)
class NewComment(BaseHandler):
    def get(self, postid):
        if self.user:
            loggedin = True
            post = Blog_Post.get_by_id(int(postid))
            postid = int(postid)
            self.render("new_comment.html",
                        page_title = "New Comment",
                        loggedin = loggedin,
                        postid = postid,
                        p = post,
                        username = self.user.name)
        else:
            self.redirect('/login')
    
    def post(self, postid):
        if self.user:
            loggedin = True
            postid = self.request.get('postid')
            author = self.request.get('author')
            content = self.request.get('content')
            
            if postid and author and content:
                ac = Comment(post_id = postid, author = author,
                             content = content, likes = 0)
                ac.put()
                time.sleep(0.1)
                self.redirect('/blog')
            else:
                error = "Please make sure field is populated"
                self.render("new_comment.html",
                        page_title = "New Comment",
                        loggedin = loggedin,
                        postid = postid,
                        p = post,
                        error = error,
                        username = self.user.name)
                
        else: 
            self.redirect('/login')

            
# /blog/editpost Handler
class EditPost(BaseHandler):
    def get(self):
        self.redirect('/login')
    
    def post(self):
        if self.user:
            loggedin = True
        if self.request.get("edit"):
            idToedit = self.request.get("edit")
            subject = self.request.get("subject")
            content = self.request.get("content")
            author = self.request.get("author")

            if subject and content and loggedin:
                p = Blog_Post.get_by_id(int(idToedit))
                p.subject = subject
                p.content = content
                if self.user.name == p.author:
                    p.put()
                    msg = "Your post has been edited."
                    self.redirect('/err?msg=%s' % msg)
                else:
                    redirect('/blog')
            else:
                error = "Please fill both fields."
                self.render("permalink.html", subject=subject,
                            content=content, page_title="Edit Post",
                            error=error, loggedin=loggedin,
                            username=self.user.name)
                
                
#/blog/newpost handler
class NewPost(BaseHandler):
    def get(self):
        if self.user:
            loggedin = True
            self.render("new_post.html",
                        page_title="New Post",
                        loggedin=loggedin,
                        username=self.user.name)
        else:
            self.redirect('/login')
        
        
    def post(self):
        if self.user:
            loggedin = True
            subject = self.request.get("subject")
            content = self.request.get("content")
            author = self.request.get("author")
            # if both fields are populated, continue
            if subject and content:
                bp = Blog_Post(subject = subject, content = content,
                               author = author, likes = 0)
                bp.put()
                time.sleep(0.1)
                self.redirect('/blog')
                self.redirect('/err?np=%s' % str(bp.key().id()))
            else:
                error = "Please fill both fields."
                self.render("new_post.html", subject=subject,
                            content=content, page_title="New Post",
                            error=error, loggedin=loggedin,
                            username=self.user.name)
        else:
            redirect('/blog')
        
            
app = webapp2.WSGIApplication([('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/?', Blog),
                               ('/blog/editpost', EditPost),
                                ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/blog/comment/([0-9]+)', NewComment),
                               ('/blog/likecomment', LikeComment),
                               ('/err', ErrPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage)
                            ])