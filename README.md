# html/javascript and html/php keycloak authentication examples

###introduction
This is a very basic example on how to authenticate against keycloak using html/js

It also demonstrates a check (introspection) on the received token using php (and cUrl)

Finally an example using html/php authentication without js is included ([php-authen.php](https://github.com/johandoornenbal/keycloak_jsclient_example/blob/master/php-authen.php))

This example leverages [OnionIoT/KeyCloak-PHP](https://github.com/OnionIoT/KeyCloak-PHP).  
An advantage may be that no redirect and additional styling of login page provided by keycloak is needed.

###setup

keycloak.json holds config

add backendconfig.json according to example

for this example I set up keycloack 2.4.0 and:
* started keycloak server with `./bin/standalone.sh -Djboss.socket.binding.port-offset=100`
* created realm "testRealm"
* created client "keycloaktest"
* created some user

to imitate an introspection on the received token by some other php application I
* created client "testBackend" using Basic authorization

###Further reading

introspection of received token:
* [https://keycloak.gitbooks.io/authorization-services-guide/content/v/2.2/topics/service/protection/token-introspection.html](https://keycloak.gitbooks.io/authorization-services-guide/content/v/2.2/topics/service/protection/token-introspection.html)

themes for the login page can be customized on the keycloak server:
* [https://keycloak.gitbooks.io/server-developer-guide/content/v/2.4/topics/themes.html](https://keycloak.gitbooks.io/server-developer-guide/content/v/2.4/topics/themes.html)
