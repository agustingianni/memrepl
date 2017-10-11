from setuptools import setup

setup(
    name="memrepl",
    version="1.0",
    url="https://github.com/agustingianni/memrepl",
    author="Agustin Gianni",
    author_email="agustin.gianni@gmail.com",
    description=("Memory inspection REPL interface"),
    license="MIT",
    keywords="memory debugger repl reverse engineering",
    py_modules=["memrepl"],
    install_requires=[
        "frida",
        "ipython",
        "hexdump"
    ],
    entry_points="""
        [console_scripts]
        memrepl=memrepl:main
    """
)
