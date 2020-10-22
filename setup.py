import os
import sys
from setuptools import setup, find_packages


def fpath(name):
    return os.path.join(os.path.dirname(__file__), name)


def read(fname):
    return open(fpath(fname)).read()


def desc():
    return read('README.md')


setup(
    name='fab_oidc2',
    version='0.0.1',
    url='https://github.com/evinaypatil/fab-oidc2/',
    project_urls={
        "Bug Tracker": "https://github.com/evinaypatil/fab-oidc2/issues",
        "Documentation": "https://github.com/evinaypatil/fab-oidc2/blob/dev-fab-oidc/README.md",
        "Source Code": "https://github.com/evinaypatil/fab-oidc2/",
    },
    license='MIT',
    author='evinaypatil',
    author_email='evinaypatil@gmail.com',
    description='Flask-AppBuilder SecurityManager for OpenIDConnect',
    long_description=desc(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data={'': ['LICENSE']},
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    setup_requires=['setuptools_scm'],
    install_requires=[
        'Flask-AppBuilder>=1.5.0',
        'flask-oidc2>=1.5.0',
        'Flask-Admin>=1.4.1'
    ],
    tests_require=[
        'nose>=1.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3',
    ],
    test_suite='nose.collector'
)
