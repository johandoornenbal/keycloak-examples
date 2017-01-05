<?php
    require_once 'OnionIoT-KeyCloak-PHP/src/KeyCloak/Grant.php';
    require_once 'OnionIoT-KeyCloak-PHP/src/KeyCloak/KeyCloak.php';
    require_once 'OnionIoT-KeyCloak-PHP/src/KeyCloak/Token.php';
    require_once 'includes/backend-call.php';

    /*
    * gets url from keycloak.js
    */
    function Login($username, $password)
    {
        $config = file_get_contents('keycloak.json');
        $kc = new \OnionIoT\KeyCloak\KeyCloak($config);
        $kc->grant_from_login($username, $password);
        $grant = $kc->grant;
        $token = $grant->access_token->_raw;

        return $token;
    }

    /*
     * gets url from keycloak.js, gets $usrpwd from backendconfig.json
     */
    function CheckToken($token)
    {
        $config = json_decode(file_get_contents('keycloak.json'), TRUE);
        $usrpwd = json_decode(file_get_contents('backendconfig.json'), TRUE);
        $tokenCheckResult = CallAPI($config['auth-server-url'] . "/realms/testRealm/protocol/openid-connect/token/introspect", $token, $usrpwd['backend-usrpwd']);
        return $tokenCheckResult;
    }

    if (strlen($_GET['username'])<1){
        require_once 'includes/login.php';
    } else {
        require_once 'includes/authenticate.php';
    }

?>



