# Authentication API

* Download python and create environment for python.

* Download [python](https://www.python.org/downloads/)
    *check python installation correctly go to the terminal or command prompt

* **python -V**  your current python  version will be printed out like this: "*Python 3.9.9*"

### In Terminal or cmd For create a environment and run

* **pip install virtualenv**

* **virtualenv venv (environment name)**

* **venv\Scripts\activate** (To activate the environment in cmd)

* **pip install -r requirements.txt**

* python (for Windows) or python3 (not for Windows): manage.py runserver

* Check the API using the blow end point

* the `api/user/*` Endpoint to create the user.


## Endpoints and HTTP Methods

| Endpoints                      | HTTP Methods |
| -------------                  |:-------------:|
|api/schema/swagger-ui/|get|
|api/schema/ |get|
|api/user/signup/                  | post         |
|api/user/signin/                     | post     |
|api/user/user/                      | get     |
|api/user/refresh/                   | post             |
|api/user/forgot/                | post          |
|api/user/reset/<str:token>/           |post          |


* api/schema/swagger-ui/ → Endpoint to work with an API in a website mode.

* In this endpoint, swagger API document help to interact with API in friendly manner. The steps to authorize the API with access token.

* first use the api/user/signup/ endpoint to create the account into the database.

* second, use the api/user/signin/ endpoint to signin into the API to get the access token.

* third, use the access token to authorize the API right coroner to top authorize option to access all the endpoints.


* api/schema/ → get the schema about the projects.

## Inside Apps

* authenticationApi

### Library

* Django Framework

* Django Rest Framework

* [drf_spectacular](https://www.bing.com/ck/a?!&&p=a60dcbdabe1258aaJmltdHM9MTY3OTE4NDAwMCZpZ3VpZD0xMmM2MGIyOC0yMmNkLTY4ZWEtMTgwOC0xOWZiMjM3ZjY5NTcmaW5zaWQ9NTE5Mg&ptn=3&hsh=3&fclid=12c60b28-22cd-68ea-1808-19fb237f6957&psq=drf+spectacular&u=a1aHR0cHM6Ly9kcmYtc3BlY3RhY3VsYXIucmVhZHRoZWRvY3MuaW8vZW4vbGF0ZXN0L3JlYWRtZS5odG1s&ntb=1)
  For API auto document and swagger(open API). This feature is not available(In processing).
