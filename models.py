import sys
import enum
from sqlalchemy import Column, ForeignKey, Integer, String, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()


class ItemCategory(enum.Enum):
    acoustic = 1
    classic = 2
    telecaster = 3
    stratocaster = 4
    lespaul = 5
    flying = 6
    hollowbody = 7
    bass = 8


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


class Item(Base):

    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    item_name = Column(String(50))
    description = Column(String(250))
    category = Column(Enum(ItemCategory))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

# engine = create_engine('sqlite:///catalog.db')
# Base.metadata.create_all(engine)
