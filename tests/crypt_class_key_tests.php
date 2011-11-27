#!/usr/bin/php
<?php

include_once('../CryptClass.php');
        
for($count=0;$count<1;$count++) {
        
        $clear_text = microtime(true).$count;
        
        echo Crypt::keygen($clear_text,32)."\n";
        echo Crypt::keygen($clear_text,24)."\n";
        echo Crypt::keygen($clear_text,16)."\n";
}
