from setuptools import setup, find_packages

setup(
    name='fluentd-requests-logging',
    version='0.1.0',
    description='A little JSON-over-HTTP export for fluentd',
    author="Etienne Lafarge",
    author_email="etienne@rythm.co",
    url="https://github.com/elafarge/django-fluentd-logging",
    # TODO: download URL
    licence='WTFPL',
    packages=find_packages(),
    zip_safe=False,
    install_requires=[

    ],
    include_package_data=True,
    classifiers=[
    'Environment :: Web Environment',
    'Intended Audience :: Developers',
    'Development Status :: 0 - Piece of Crap',
    'License :: OSI Approved :: WTFPL License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: Utilities',
    'Topic :: Django',
    'Topic :: Middleware',
    'Topic :: Logging',
  ],
)
