import enum

from sqlalchemy import Column, ForeignKey, Integer, String, Enum
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

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
    email = Column(String)


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    item_name = Column(String(50))
    description = Column(String(250))
    category = Column(Enum(ItemCategory))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'item_name': self.item_name,
            'description': self.description,
            'category': self.category.name,
            'added_by': self.user.username,
        }


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
