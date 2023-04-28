from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, session, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from forms import RegisterForm, CreatePostForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
# login_manager = LoginManager()
# login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# create user table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, unique=True, nullable=False)

    posts = relationship("BlogPost", back_populates="author", lazy="dynamic")


##CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()


# decorator function for admin login required
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if session['user'] == 1:
                return f(*args, **kwargs)
            else:
                return abort(403)
        except Exception as e:
            print(e)
            return abort(403)

    return decorated_function


@app.route('/')
def get_all_posts():
    isadmin = False
    posts = BlogPost.query.all()
    if 'user' in session and session["user"] == 1:
        isadmin = True
    print(posts[0].author.name)
    return render_template("index.html", all_posts=posts, admin=isadmin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        try:
            hash_pass = generate_password_hash(
                password=form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=hash_pass
            )
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            flash(u"username/email already exist!", 'error')
            return redirect(url_for("register"))
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
# @login_manager.user_loader()
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        user_pass = form.password.data
        try:
            user = db.session.query(User).filter(User.email == form.email.data).first()
            if check_password_hash(user.password, user_pass) and form.email.data == user.email:
                session["user"] = user.id
                print("logged in, user: ", user.name)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Invalid email", "error")
                return redirect(url_for("login"))
        except:
            flash("Invalid email", "error")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    session.pop("user", None)
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = db.session.query(BlogPost).filter(BlogPost.id == post_id).first()
    isadmin = False
    if "user" in session and session["user"] == 1:
        isadmin = True
    form = CommentForm()
    return render_template("post.html", post=requested_post, admin=isadmin, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.id == int(session["user"])).first()
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        print("i am here")
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post_data = db.session.query(BlogPost).get(post_id)
    form = CreatePostForm(
        title=post_data.title,
        subtitle=post_data.subtitle,
        img_url=post_data.img_url,
        author=post_data.author,
        body=post_data.body
    )
    print()
    try:
        if form.validate_on_submit() and request.method == "POST":
            post_data.title = form.title.data
            post_data.subtitle = form.subtitle.data
            post_data.img_url = form.img_url.data
            post_data.body = request.form.get("ckeditor")
            post_data.date = date.today().strftime("%B %d, %Y")
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            print(form.errors)
    except Exception as e:
        print(e)
        print("error in editing post")

    return render_template("edit-post.html", form=form, post_data=post_data)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
