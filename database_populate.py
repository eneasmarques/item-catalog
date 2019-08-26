from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from config_db import DATABASE_URL

from database_setup import Users, Restaurant, Base, MenuItem

engine = create_engine(DATABASE_URL)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)

user = Users(name="root", email="root@gmail.com")
session.add(user)
session.commit()

# Menu for UrbanBurger
restaurant1 = Restaurant(name="Urban Burger", user=user)

session.add(restaurant1)
session.commit()

menuItem2 = MenuItem(name="Veggie Burger",
                     description="""
                     Juicy grilled veggie patty with tomato mayo and lettuce
                     """,
                     price="$7.50", course="Entree",
                     restaurant=restaurant1, user=user)

session.add(menuItem2)
session.commit()


menuItem1 = MenuItem(name="French Fries",
                     description="with garlic and parmesan",
                     price="$2.99", course="Appetizer",
                     restaurant=restaurant1, user=user)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(name="Chicken Burger",
                     description="""
                     Juicy grilled chicken patty with tomato mayo and lettuce
                     """,
                     price="$5.50", course="Entree",
                     restaurant=restaurant1, user=user)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(name="Chocolate Cake",
                     description="fresh baked and served with ice cream",
                     price="$3.99", course="Dessert",
                     restaurant=restaurant1, user=user)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(name="Sirloin Burger",
                     description="Made with grade A beef",
                     price="$7.99", course="Entree",
                     restaurant=restaurant1, user=user)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(name="Root Beer",
                     description="16oz of refreshing goodness",
                     price="$1.99", course="Beverage",
                     restaurant=restaurant1, user=user)

session.add(menuItem5)
session.commit()

menuItem6 = MenuItem(name="Iced Tea", description="with Lemon",
                     price="$.99", course="Beverage",
                     restaurant=restaurant1, user=user)

session.add(menuItem6)
session.commit()

menuItem7 = MenuItem(name="Grilled Cheese Sandwich",
                     description="On texas toast with American Cheese",
                     price="$3.49", course="Entree",
                     restaurant=restaurant1, user=user)

session.add(menuItem7)
session.commit()

menuItem8 = MenuItem(name="Veggie Burger",
                     description=""""
                    Made with freshest of ingredients and home grown spices
                    """,
                     price="$5.99", course="Entree",
                     restaurant=restaurant1, user=user)

session.add(menuItem8)
session.commit()


# Menu for Super Stir Fry
restaurant2 = Restaurant(user=user, name="Super Stir Fry")

session.add(restaurant2)
session.commit()


menuItem1 = MenuItem(name="Chicken Stir Fry",
                     description="""
                    With your choice of noodles
                    vegetables and sauces
                    """,
                     price="$7.99", course="Entree",
                     restaurant=restaurant2, user=user)

session.add(menuItem1)
session.commit()

menuItem2 = MenuItem(
    name="Peking Duck",
    description="""
    A famous duck dish from Beijing[1] that has been prepared
    since the imperial era. The meat is prized for its thin, crisp skin,
    with authentic versions of the dish serving mostly the skin and little
    meat, sliced in front of the diners by the cook
    """,
    price="$25", course="Entree", restaurant=restaurant2, user=user)

session.add(menuItem2)
session.commit()

menuItem3 = MenuItem(
    name=""""
    Spicy Tuna Roll", description="Seared rare ahi, avocado, edamame,
    cucumber with wasabi soy sauce """,
    price="15", course="Entree", restaurant=restaurant2, user=user)

session.add(menuItem3)
session.commit()

menuItem4 = MenuItem(name="Nepali Momo ",
                     description="""
                     Steamed dumplings made with vegetables,
                     spices and meat.
                     """,
                     price="12", course="Entree",
                     restaurant=restaurant2, user=user)

session.add(menuItem4)
session.commit()

menuItem5 = MenuItem(
    name="Beef Noodle Soup",
    description="""
    A Chinese noodle soup made of stewed or red braised beef,
    beef broth, vegetables and Chinese noodles.
    """,
    price="14", course="Entree", restaurant=restaurant2, user=user)

session.add(menuItem5)
session.commit()

menuItem6 = MenuItem(
    name="Ramen",
    description=""""
    a Japanese noodle soup dish. It consists of Chinese-style
    wheat noodles served in a meat - or (occasionally) fish-based broth,
    often flavored with soy sauce or miso,
    and uses toppings such as sliced pork, dried seaweed,
    kamaboko, and green onions.
    """,
    price="12", course="Entree", restaurant=restaurant2, user=user)

session.add(menuItem6)
session.commit()
