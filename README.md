# Poynt API - Python Sample
A simple Python sample demonstrating the usage of Poynt Cloud APIs.

## Installing

```
$ sudo pip install PyJWT
$ sudo pip install cryptography
$ sudo pip install requests
$ sudo pip install rsa
$ sudo pip install PIL
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

If the script fails with `requests.exceptions.ConnectionError: ('Connection aborted.', error(54, 'Connection reset by peer'))` you may need to update your python installation to support TLS 1.2. If you use Homebrew, follow these steps:

1. `brew update`
2. `brew install openssl`
3. `brew link openssl --force`
4. `brew install python --with-brewed-openssl`

Once done run `which python` in Terminal and check the python script to make sure the path to your python binary matches (i.e. `#!/usr/bin/python` or `#!/usr/local/bin/python`)
