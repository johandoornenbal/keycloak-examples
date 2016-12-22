<?php
    require_once 'includes/backend-call.php';

    $token = $_GET[token];
    $tokenCheckResult = CallAPI("http://localhost:8180/auth/realms/testRealm/protocol/openid-connect/token/introspect", $token);

?>

<p>
    Token Check result (json):
</p>
<textarea id="result" style="width: 50%; height: 40%;"><?= $tokenCheckResult ?></textarea>
<p>
    Token Check result (as dump of php var):
</p>
<textarea id="resultFormatted" style="width: 50%; height: 70%;"><?php var_dump(json_decode($tokenCheckResult)) ?></textarea>