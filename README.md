# zkp-user-centric-id-mgmt
Zero-knowledge proof with User-centric identity management

# ZKP
Zero-Knowledge password-based authentications with a cache of temporary, asymmetric credentials

## How to run the solution

 - First, enter the directory `solution`.

 - First, you will need to create a virtual environment where you will install all the needed dependencies:
    ```bash
    $ virtualenv venv
    $ source venv/bin/activate
    $ pip install -r requirements.txt
    ```

 - Then, to run each one of the entities, you will need 3 terminals, one to run each one of them:
    ```bash
    # on each terminal, enter the virtual environment
    $ source venv/bin/activate

    # to run the IdP
    $ cd idp
    $ python IdP.py

    # to run the SP
    $ cd sp
    $ python SP.py

    # to run the helper application
    $ cd helper
    $ python helper_app.py
    ```

 - For default, they will bind to the following URLs:
    - IdP: http://127.0.0.1:8082
    - SP: http://127.0.0.1:8081
    - helper application: http://127.1.2.3:1080

    However, you can change these values easily in the source code


 - Take into consideration that the IdP will contact the helper application using the host name `zkp_helper_app`, which means that you must define this host name on your local DNS, linked to the IP `127.1.2.3`. On linux, you just have to had the following line to the `/etc/hosts` file:
    ```bash
    127.1.2.3  zkp_helper_app
    ```

 - For testing purposes, there are some constants defined on each entity that are set to low values. You can change them (they are on the top of each of the following files):
    - SP.py:
       - COOKIE_TTL: the current value is 200 seconds, and represents the max-age of the session cookie used by the SP.
    - IdP.py:
       - MIN_ITERATIONS_ALLOWED: the current value is 300, and represents the minimum iterations allowed by the IdP for the ZKP protocol (value of N).
       - MAX_ITERATIONS_ALLOWED: the current value is 1000, and represents the maximum iterations allowed by the IdP for the ZKP protocol (value of N).
       - KEYS_TIME_TO_LIVE: the current value is 10 minutes, and represents the maximum time that a public key will be valid on the IdP.
    - helper_application.py:
       - MIN_ITERATIONS_ALLOWED: the current value is 200, and represents the minimum iterations allowed by the helper application for the ZKP protocol (value of N).
       - MAX_ITERATIONS_ALLOWED: the current value is 500, and represents the maximum iterations allowed by the helper application for the ZKP protocol (value of N).

 - To register a new user on the helper application, you must access the URL `http://zkp_helper_app:1080/register`.
    - There is already one registered that you can use: 
       - Username: `escaleira`
       - Password: `olaadeus`

 - To register a new user on the IdP, you must access the SQLite database file `idp.db`, and add a new user to the users table:
    ```sql
    insert into user values ('<username>', '<password>');
    ```
    - There is already one registered that you can use: 
        - Username: `escaleira`
        - Password: `asfasdjfpoijasdfoijaspodifjajdpoij`
