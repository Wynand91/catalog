from flask import Flask, render_template
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import SingletonThreadPool

from models import Base, Item

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db'+'?check_same_thread=False', poolclass=SingletonThreadPool)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def homepage():
    items = session.query(Item).all()
    return render_template('landing_page.html', items=items)


@app.route('/category/<category_name>/')
def category_view(category_name):
    items = session.query(Item).filter(Item.category.endswith(category_name)).all()
    return render_template('category_list.html', items=items)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
