from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Style, Base, Commodity, User

engine = create_engine('sqlite:///style.db')
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
User1 = User(name="Ashish", email="sharif.ashu1997@gmail.com")

style1 = Style(user_id="1", name="Puma")
session.add(style1)
session.commit()

commodity1 = Commodity(name="loafers", description="Brown", price="$20",
                   materialtype="sheepskin", style=style1)

session.add(commodity1)
session.commit()

commodity2 = Commodity(name="canvas", description="Blue",
                   price="$25", materialtype="synthetic leather", style=style1)

session.add(commodity2)
session.commit()

commodity3 = Commodity(name="formals ", description="Black",
                   price="$35", materialtype="microfiber leather", style=style1)

session.add(commodity3)
session.commit()

style2 = Style(user_id="1", name="Woodland")
session.add(style2)
session.commit()

commodity1 = Commodity(name="loafers", description="Blue",
                   price="$15", materialtype="sheepskin", style=style2)

session.add(commodity1)
session.commit()

commodity2 = Commodity(name="canvas", description="Red",
                   price="$30", materialtype="synthetic leather", style=style2)

session.add(commodity2)
session.commit()

commodity3 = Commodity(name="formals", description="Brown",
                   price="$36", materialtype="microfiber leather", style=style1)

session.add(commodity3)
session.commit()

style3 = Style(user_id="1", name="Nike")
session.add(style3)
session.commit()

commodity1 = Commodity(name="loafers", description="Green",
                   price="45", materialtype="sheepskin", style=style3)

session.add(commodity1)
session.commit()

commodity2 = Commodity(name="canvas", description="yellow",
                   price="$25", materialtype="synthetic leather", style=style1)

session.add(commodity2)
session.commit()

commodyit3 = Commodity(name="formals", description="tan",
                   price="$35", materialtype="microfiber leather", style=style1)

session.add(commodity3)
session.commit()

style4 = Style(user_id="1", name="provogue")
session.add(style4)
session.commit()

commodity1 = Commodity(name="loafers", description="grey",
                   price="$31", materialtype="sheepskin", style=style4)

session.add(commodity1)
session.commit()

commodity2 = Commodity(name="canvas", description="orange",
                   price="$48", materialtype="synthetic leather", style=style4)

session.add(commodity2)
session.commit()

commodity3 = Commodity(name="formals", description="green",
                   price="$75", materialtype="microfiber leather", style=style4)

session.add(commodity3)
session.commit()

print("added commodity details!")
