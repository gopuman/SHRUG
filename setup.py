from setuptools import setup, find_packages


setup(
    name='SHRUG',
    version='0.0.1',
    license='MIT',
    author=["Gopal Nambiar",
            "Shreyas Madhav",
            "Ruthuvikas Ravikumar",
           ],
    author_email='gopalnambiar2@gmail.com',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/gopuman/SHRUG',
    keywords='Anonymization project',
    install_requires=[
          'scapy',
          'yacryptopan',
          'numpy',
      ],

)
