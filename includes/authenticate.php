<?php

$token = Login($_GET['username'], $_GET['password']);

if (strlen($token) > 0) {
    $authenticated = true;
    $tokenCheckResult = CheckToken($token);
} else {
    $authenticated = false;
}

if ($authenticated) {
    ?>
    <h2>
        Authenticated; now checking received token ...
    </h2>

    <div>
        <div>
            Token Check result (as dump of php var):
        </div>
        <textarea id="resultFormatted" style="width: 50%; height: 70%;"><?php var_dump(json_decode($tokenCheckResult)) ?></textarea>
    </div>

    <?php
} else {

    ?>
    <h2>
        Not authenticated
    </h2>
    <p>
        <a href="php-authen.php">try again</a>
    </p>

    <?php
}


