<?php
    require_once 'OnionIoT-KeyCloak-PHP/src/KeyCloak/Grant.php';
    require_once 'OnionIoT-KeyCloak-PHP/src/KeyCloak/KeyCloak.php';
    require_once 'OnionIoT-KeyCloak-PHP/src/KeyCloak/Token.php';
    require_once 'includes/backend-call.php';

    function Login($username, $password)
    {
        $config = file_get_contents('keycloak.json');
        $kc = new \OnionIoT\KeyCloak\KeyCloak($config);
        $kc->grant_from_login($username, $password);
        $grant = $kc->grant;
        $token = $grant->access_token->_raw;

        return $token;
    }

    function CheckToken($token)
    {
        $tokenCheckResult = CallAPI("http://localhost:8180/auth/realms/testRealm/protocol/openid-connect/token/introspect", $token);
        return $tokenCheckResult;
    }

    if (strlen($_GET['username'])<1){
        require_once 'includes/login.php';
    } else {
        require_once 'includes/authenticate.php';
    }

?>



