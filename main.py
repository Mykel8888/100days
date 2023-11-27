from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user,login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import CreatePostForm, RegisteredForm, LoginForm,CommentForm
#from config import FLASK_DEBUG, SQLALCHEMY_DATABASE_URI, SECRETE_KEY, Email, Password
import yagmail
'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''
app = Flask(__name__)
app.config['FLASK_DEBUG'] = 1


#app.config['SECRET_KEY']=SECRETE_KEY

#app.config['SQLALCHEMY_DATABASE_URI']= SQLALCHEMY_DATABASE_URI

app.config['SECRET_KEY'] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'

db = SQLAlchemy()
db.init_app(app)

Email_from = 'michaelbible05@gmail.com'
password = 'xcof fvdn xawe spez'


ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configures Flask-Login
login_manager=LoginManager()
login_manager.init_app(app)

# CONNECT TO DB



class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String(100), unique=True)
    password= db.Column(db.String(100))
    name = db.Column(db.String(100))

  # this we create a blog post object attached to each user
    #THe "author refer to the "author" refer to th author property in thr Blogpost class
    posts =relationship("BlogPost",back_populates="author")
    comment = relationship("Comments", back_populates="comment_author")
# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # to able to find the blog post by a user we need to create foreign key such as:
    # user.id, its refer to tablename of the user
    author_id=db.Column(db.Integer, db.ForeignKey("users.id")) #Note this author need to be edited to .name in index and post html
    #Create reference to the User object , the "posts", refer to the post property in the User class.
    author = relationship("User", back_populates='posts')


    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comment = relationship("Comments", back_populates="parent_post")

class Comments(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    # to obtain the author id
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comment")
# TODO: Create a User table for all your registered users.
    # to obtain the post id
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comment")
    text = db.Column(db.Text, nullable=False)



with app.app_context():
    db.create_all()

#to adding image to the comment section
gravatar=Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


#admin only decorator i.e only the admin with first account can access those pages
def admin_only(func):
    @wraps(func)
    def decorator_function(*args, **kwargs):
        #if id is not 1 return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #otherwise continue wuth the route function
        return func(*args, **kwargs)
    return decorator_function

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    form=RegisteredForm()


    if form.validate_on_submit():
        email = form.email.data
        #if the email already used
        user = db.session.execute(db.select(User).where(User.email == email)).scalars().all()
        if user:
            flash("you have signup with the email already you can sign in")
            return redirect(url_for("login"))

        hash_and_salted_password = generate_password_hash(
            password=form.password.data,
            method="pbkdf2:sha256",
            salt_length= 8
            )
        new_user= User(
            email=email,
            name= form.name.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        #this code will authenticate the user with flask login
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

#current_user is in hearder
    return render_template("register.html", form=form, current_user=current_user )


# TODO: Retrieve a user from the database based on their email.
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route('/login', methods=['POST', 'GET'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        email=form.email.data
        password=form.password.data
        result=db.session.execute(db.select(User).where(User.email == email))
        users= result.scalars().all()
        #the email in db is unique so will only have one result
        if not users:
            flash("the email is not exist try again")
            return redirect(url_for("login"))
        #because we have different 2classes storage in db (blogposts, users)
        try:
            if not check_password_hash(users.password, password):
                flash("the password not correct, please try again")
                return redirect(url_for("login"))
            else:
                login_user(users)
                return redirect( url_for('get_all_posts', name=users.name))
        except AttributeError: #should incase its idnetify datas as list
            users=users[0]
            if not check_password_hash(users.password, password):
                flash("the password not correct, please try again")
                return redirect(url_for("login"))
            else:
                login_user(users)
                return redirect(url_for('get_all_posts', name=users.name))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user() # its a direct function from libary
    return redirect(url_for('get_all_posts'))




@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    #add comment to the root
    comment_form= CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("you need to  login or register before comment")
            return redirect(url_for("login"))

        new_comment=Comments(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post= requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']
        print(name)
        send_mail(email, name, phone, message)
        return redirect(url_for('get_all_posts'))

    return render_template("contact.html", current_user=current_user)


def send_mail(email, name, phone, message):
    to_admin=(f"Subject:new message\n\nemail:{email}\nname: {name}\nphone: {phone}\nmessage: {message}")
    to_user=(f"Subject:new message\n\nthanks for the filling  the contact form, it an honour cause its will go a long way, if you need a python coding website like this contact me i will do it freely for you, Thanks")
    with yagmail.SMTP(Email_from, password) as connection:
        connection.send(to=Email_from, subject="contact details", contents=to_admin)
        connection.send(to=email, subject="Michaels'_blog", contents=to_user)
        print("successfully sent")


if __name__ == "__main__":
    app.run(debug=True, port=5002)





