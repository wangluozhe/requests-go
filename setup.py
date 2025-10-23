#!/usr/bin/env python
from setuptools import setup, find_packages
from codecs import open
import glob
import os

data_files = []
directories = glob.glob('requests_go/tls_client/dependencies/')
for directory in directories:
    files = glob.glob(directory+'*')
    data_files.append(('requests_go/tls_client/dependencies', files))

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "requests_go", "__version__.py"), "r", "utf-8") as f:
    exec(f.read(), about)

with open("README.md", "r", "utf-8") as f:
    readme = f.read()

setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    description=about["__description__"],
    license=about["__license__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    python_requires=">=3.7",
    long_description=readme,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        '': ['*'],
    },
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries",
    ],
    install_requires=[
        "requests>=2.28.1",
        "six>=1.16.0",
        "PySocks>=1.7.1"
    ]
)
