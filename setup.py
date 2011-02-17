from setuptools import setup, find_packages
setup(
    name='Circles',
    version='1.0',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'Flask',
        'Flask-SQLAlchemy',
        'wtforms',
        'FLask-Testing',
    ]
)
