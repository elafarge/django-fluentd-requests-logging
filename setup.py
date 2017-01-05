from setuptools import setup, find_packages

setup(
    name='django-fluentd-requests-logging',
    version='0.4.0',
    description='A little JSON-over-HTTP Django request log export for fluentd',
    author="Etienne Lafarge",
    author_email="etienne@rythm.co",
    url="https://github.com/elafarge/django-fluentd-requests-logging",
    # TODO: download URL
    licence='MIT',
    packages=find_packages(),
    zip_safe=False,
    install_requires=[
        'requests==2.9.1',
        'six==1.10.0',
        'Werkzeug==0.11.9',
    ],
    include_package_data=True,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Development Status :: 1 - Beta',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
        'Topic :: Django',
        'Topic :: Middleware',
        'Topic :: Logging',
        'Topic :: Fluentd',
  ],
)
