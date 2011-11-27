#!/usr/bin/php
<?php

include_once('../CryptClass.php');
        
$clear_text = array(
    "data_+/=','-_,".md5('X'.microtime(true)),
    mt_rand(0,10000000000000),
    array(1,2,8),
    array('foo'=>array('cat','dog')),
);

// Preset the key in the static function
Crypt::$key = md5(microtime(true));
$encrypted = Crypt::encrypt($clear_text);
$decrypted = Crypt::decrypt($encrypted);

echo $encrypted."\n\n";
print_r($decrypted);


// Use a different key per static call
Crypt::$key = null;
$key = md5(microtime(true));
$encrypted = Crypt::encrypt($clear_text,$key);
$decrypted = Crypt::decrypt($encrypted,$key);

echo $encrypted."\n\n";
print_r($decrypted);
