# Flask-AppBuilder SecurityManager for OpenIDConnect

![PyPI](https://img.shields.io/pypi/v/fab_oidc2?style=flat-square) 

Wrapper for [flask_oidc2](http://flask-oidc2.readthedocs.io/en/latest/) that exposes a `SecurityManager` for use with any Flask-AppBuilder app.

It will allow your users to login with OpenIDConnect providers such as Auth0, Okta or Google Apps. This version of the code extracts the roles information of OIDC ID token, and allow a request to continue only if the role is available on the application.

This is roughly inspired by the code in this [stackoverflow](https://stackoverflow.com/a/47787279/44252) answer. (MIT Licenced © [thijsfranck](https://stackoverflow.com/users/8905583/thijsfranck))

## Usage

### Generic

Just override the default security manager in your Flask Appbuilder app.

```python
from fab_oidc2.security import OIDCSecurityManager

appbuilder = AppBuilder(app, db.session, security_manager_class=OIDCSecurityManager)
```

### [Airflow]
Airflow provides a hook in the `webserver_config.py` file where you can specify a security manager class.
In `webserver_config.py` import the OIDCSecurityManager and set
```python
from fab_oidc2.security import AirflowOIDCSecurityManager
...
SECURITY_MANAGER_CLASS = AirflowOIDCSecurityManager
```

Airflow now requires that your `SECURITY_MANAGER_CLASS` is a subclass of `AirflowSecurityManager`.
Use the special `AirflowOIDCSecurityManager` that is only defined if you're using this library alongside Airflow.

### [Superset]
Superset works in a a similar way. Just as in Airflow,
`SECURITY_MANAGER_CLASS` needs to be a subclass of `SupersetSecurityManager`
the config is in a file called `superset_config.py` and the hook is called
`CUSTOM_SECURITY_MANAGER`. There now exists a special
`SupersetOIDCSecurityManager` that is only defined if you are using this
library alongside Superset.

```python
from fab_oidc2.security import SupersetOIDCSecurityManager
...
CUSTOM_SECURITY_MANAGER = SupersetOIDCSecurityManager
```


## Settings
The settings are the same as the [flask_oidc settings][flask_oidc_settings], so look there for a reference.

if you're happy with [flask_oidc]'s defaults the only thing you'll really need is something like:

```python
OIDC_CLIENT_SECRETS = '/path/to/client_secret.json'
```

see the [flask_oidc manual client registration][flask_oidc_manual_config] docs for how to generate or write one.

### OIDC Field configuration

If you like to change the default OIDC field that will be used as a username,
first name, last name and granting access via OIDC roles, you can set the following env var in the shell you run
your process:

```bash
export USERNAME_OIDC_FIELD='preferred_username'
export FIRST_NAME_OIDC_FIELD='given_name'
export LAST_NAME_OIDC_FIELD='family_name'
export ENABLE_ROLE_OIDC_ACCESS='true'
export ROLES_OIDC_FIELD='roles'
```

#### Project status

This is a fork of the project [ministryofjustice/fab-oidc]: https://github.com/ministryofjustice/fab-oidc


Copyright © 2018 HM Government (Ministry of Justice Digital Services). See LICENSE.txt for further details.


[flask_oidc2]: http://flask-oidc2.readthedocs.io/en/latest/
[flask_oidc2_settings]: http://flask-oidc2.readthedocs.io/en/latest/#settings-reference
[flask_oidc2_manual_config]: http://flask-oidc2.readthedocs.io/en/latest/#manual-client-registration
[Airflow]: https://airflow.apache.org/
 [Superset]: https://superset.incubator.apache.org/
