from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import *

engine = create_engine('sqlite:///games_db.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Delete Platform if exisitng.
session.query(PlatForm).delete()
# Delete GameTitle if exisitng.
session.query(GameTitle).delete()
# Delete User if exisitng.
session.query(User).delete()

# Create sample users data
User1 = User(name="Kata Akhil",
             email="kata.akhil@gmail.com",)
session.add(User1)
session.commit()
print ("Successfully Add First User")
# Create sample Platform
Platform1 = PlatForm(name="Microsoft Xbox-360",
                     user_id=1)
session.add(Platform1)
session.commit()

Platform2 = PlatForm(name="ubuntu",
                     user_id=1)
session.add(Platform2)
session.commit

Platform3 = PlatForm(name="Play Station 4",
                     user_id=1)
session.add(Platform3)
session.commit()

Platform4 = PlatForm(name="Sega Genesis",
                     user_id=1)
session.add(Platform4)
session.commit()

Platform5 = PlatForm(name="IOS",
                     user_id=1)
session.add(Platform5)
session.commit()

Platform6 = PlatForm(name="Nuon",
                     user_id=1)
session.add(Platform6)
session.commit()

# different games for different platforms
# along with description
Game1 = GameTitle(name="Assassins Creed Odessy",
                  description="9.2",
                  publisher="mini clip",
                  platformid=1,
                  user_id=1)
session.add(Game1)
session.commit()

Game2 = GameTitle(name="8 ball pool",
                  description="online multi player game with logins",
                  publisher="mini clip",
                  platformid=2,
                  user_id=1)
session.add(Game2)
session.commit()

Game3 = GameTitle(name="Far Cry 5",
                  description="first person shooter",
                  publisher="senises",
                  platformid=3,
                  user_id=1)
session.add(Game3)
session.commit()

Game4 = GameTitle(name="Need for Speed: Most Wanted",
                  description="car racing",
                  publisher="tech soft sols",
                  platformid=4,
                  user_id=1)
session.add(Game4)
session.commit()

Game5 = GameTitle(name="Fallout 4",
                  description="action role-play",
                  publisher="visual studios",
                  platformid=5,
                  user_id=1)
session.add(Game5)
session.commit()

Game6 = GameTitle(name="Call of Duty: Black Ops 4",
                  description="first-person shooter",
                  publisher="origin studios",
                  platformid=6,
                  user_id=1)
session.add(Game6)
session.commit()
print("Your games database has been inserted!")
