from flask import Flask, render_template
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Item
app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def homepage():
    items = session.query(Item).all()
    return render_template('landing_page.html', items=items)


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0', port=8000)
