import sys
from enum import Enum
from babel import lazy_gettext as _
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy_utils import ChoiceType

Base = declarative_base()


class ItemCategory(Enum):
    acoustic = 1
    classic = 2
    telecaster = 3
    stratocaster = 4
    lespaul = 5
    flying = 6
    hollowbody = 7
    bass = 8


ItemCategory.acoustic.label = _(u'Acoustic')
ItemCategory.classic.label = _(u'Classic')
ItemCategory.telecaster.label = _(u'Telecaster')
ItemCategory.stratocaster.label = _(u'Stratocaster')
ItemCategory.lespaul.label = _(u'Les paul')
ItemCategory.flying.label = _(u'Flying')
ItemCategory.hollowbody.label = _(u'Hollow body')
ItemCategory.bass.label = _(u'Bass')


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
    category = Column(ChoiceType(ItemCategory, impl=Integer()))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
