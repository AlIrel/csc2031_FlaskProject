from flask import Flask

app = Flask(__name__)

from blog.views import blog_blueprint
app.register_blueprint(blog_blueprint)

from users.views import users_blueprint
app.register_blueprint(users_blueprint)

from main.views import main_blueprint
app.register_blueprint(main_blueprint)

if __name__ == '__main__':
    app.run()
