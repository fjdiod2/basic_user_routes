import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "basic_user_routes",
    version = "0.0.1",
    author = "Sergey Solovyev",
    author_email = "fjdiod2@gmail.com",
    description = ("Basic sign up/sign in routes for FastAPI"),
    url = "https://github.com/fjdiod2/basic_user_routes",
    packages=['basic_user_routes',],
    long_description=read('README'),
    classifiers=[
        "Development Status :: 1 - Beta",
    ],
)