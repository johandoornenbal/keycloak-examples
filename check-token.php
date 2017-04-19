<?php
    require_once 'includes/backend-call.php';

    $token = $_GET[token];
    /*
    * gets url from keycloak.js, gets $usrpwd from backendconfig.json
    */
    $config = json_decode(file_get_contents('keycloak.json'), TRUE);
    $usrpwd = json_decode(file_get_contents('backendconfig.json'), TRUE);
    $tokenCheckResult = CallAPI($config['auth-server-url'] . "/realms/".$usrpwd['realm']."/protocol/openid-connect/token/introspect", $token, $usrpwd['backend-usrpwd']);

?>

<p>
    Token Check result (json):
</p>
<textarea id="result" style="width: 50%; height: 40%;"><?= $tokenCheckResult ?></textarea>
<p>
    Token Check result (as dump of php var):
</p>
<textarea id="resultFormatted" style="width: 50%; height: 70%;"><?php var_dump(json_decode($tokenCheckResult)) ?></textarea>