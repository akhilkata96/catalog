import sys
import os
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(220), nullable=False)


class PlatForm(Base):
    __tablename__ = 'platform'
    id = Column(Integer, primary_key=True)
    name = Column(String(300), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="platform")

    @property
    def serialize(self):
        """Return objects data in easily serializeable formats"""
        return {
            'name': self.name,
            'id': self.id
        }


class GameTitle(Base):
    __tablename__ = 'gamename'
    id = Column(Integer, primary_key=True)
    name = Column(String(350), nullable=False)
    description = Column(String(150))
    publisher = Column(String(10))
    platformid = Column(Integer, ForeignKey('platform.id'))
    platform = relationship(
        PlatForm, backref=backref('gamename', cascade='all, delete'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="gamename")

    @property
    def serialize(self):
        """Return objects data in easily serializeable formats"""
        return {
            'name': self. name,
            'description': self. description,
            'publisher': self. publisher,
            'id': self. id
        }

engin = create_engine('sqlite:///games_db.db')
Base.metadata.create_all(engin)
