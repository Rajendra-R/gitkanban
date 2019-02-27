from setuptools import setup, find_packages

setup(
    name="gitkanban",
    version="0.0.1",
    packages=["gitkanban"],
    url="https://github.com/deep-compute/gitkanban",
    install_requires=[
        "basescript==0.2.8",
        "PyGithub==1.43.5",
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
