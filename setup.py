from setuptools import setup, find_packages


setup(
    long_description="""SHRUG is a simple Python library that lets users anonymize source and destination IP addresses in packet traces. As of the current release, SHRUG supports the following anonymization algorithms:

1. Randomizer algorithm (**randomizer**)
2. Prefix Preserving algorithm (**prefAnon**) [Using [CryptoPAn](https://github.com/Yawning/cryptopan)]
3. BlackMarker algorithm (**blackMarker**)
4. Permutation algorithm (**permutation**)
5. Truncation algorithm (**truncation**)
6. Reverse Truncation algorithm (**revTruncation**)

## Usage
- Install the package using pip
```
pip install SHRUG-anon
```

- Import the module and the anonymization methods
```
>>> from SHRUG_anon import anonalgos
```

- The read_from method can be used to read a .pcap or .tcpdump file
```
>>> input_pks = anonalgos.read_from("/path/to/pcap/tcpdump/file")
```

- Use one of the six anonymization algorithms on the packet capture stored in the previous step, and store the anonymized packets.
```
>>> anonalgos.randomizer(input_pks)
>>> anonalgos.write_to("/path/to/anonymized/packets/.pcap/.tcpdump")
```

- NOTE: The truncation and reverse truncation algorithms require a second parameter, i.e., the number of bits to be truncated.
```
>>> anonalgos.truncation(input_pks, 12)
``` """,
    long_description_content_type='text/markdown',
    name='SHRUG_anon',
    version='1.0.1',
    license='MIT',
    author=["Gopal Nambiar",
            "Shreyas Madhav",
            "Ruthuvikas Ravikumar",
           ],
    author_email='gnambiar@ucdavis.edu',
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
