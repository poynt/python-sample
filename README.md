# Poynt API - Python Sample
A simple Python sample demonstrating the usage of Poynt Cloud APIs.

## Installing

```
$ sudo pip install PyJWT
$ sudo pip install cryptography
$ sudo pip install requests
$ sudo pip install rsa
```

## Usage

```
./src/PoyntAPI.py
```

Note that you might need to give executable permissions to the file or you
can just run:

```
python src/PoyntAPI.py
```
Optional args:
* -v for verbose logging
* -e ci or live to switch between live and ci environments

NOTE: Default configs are provided to help you quickly run and see how this works.
Please update config/poynt.ini with your application settings so you have better
control on your application and test business data.
