from setuptools import setup, find_packages

setup(
    name="gitkanban",
    version="0.0.2",
    packages=["gitkanban"],
    url="https://github.com/deep-compute/gitkanban",
    install_requires=[
        "basescript==0.2.8",
        "PyGithub==1.43.5",
        "python-dateutil==2.8.0",
        "requests==2.20.1",
        "pylru==1.1.0",
        "pytz==2018.3",
        "numpy==1.16.2",
        "SQLAlchemy==1.3.3",
        "SQLAlchemy-Utils==0.33.11",
    ],
    author="deep-compute",
    author_email="contact@deepcompute.com",
    description="A tool to enhance Github issue management with Kanban flow",
    keywords=["gitkanban"],
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "gitkanban = gitkanban:main",
        ]
    }
)
