#!/usr/bin/php
<?php

include_once('../CryptClass.php');

$option_permutations = random_option_permutations(10000);

$tally = array();

foreach($option_permutations as $options) {
        
        $key = md5(microtime(true));
        
        $CryptClass = null;
        $CryptClass = new CryptAesClass($key,$options);
        
        $clear_text = array(
            "data_+/=','-_,".md5('X'.microtime(true)),
            mt_rand(0,10000000000000),
            hex2bin( md5('X'.microtime(true)) ),
            //file_get_contents('image.png'),
            null,
            false,
            true,
            array(1,2,3,4,5,8),
            array('foo'=>array('cat','dog')),
            hex2bin( md5('Y'.microtime(true)) ),
        );
        
        $encrypted = $CryptClass->encrypt($clear_text); 
        $encrypt_decrypt = $CryptClass->decrypt($encrypted);
        
        //echo $encrypted."\n";
        
        if($clear_text !== $encrypt_decrypt){
                
                echo 'Failed to encrypt / decrypt '.$clear_text."\n";
                
                foreach($options as $key=>$value) {
                        if($value) {
                                $tally['true'][$key]++;
                        } else {
                                $tally['false'][$key]++;
                        }
                }
                //print_r($options);
        } else {
                echo '.';
        }
}

print_r($tally);

function random_option_permutations($iterations) {
        
        $options = array(
            'compress',
            'url_safe',
            'base64_encode',
            'test_decrypt_before_return',
        );
        
        $perms = array();
        
        for($count=0;$count<$iterations;$count++) {
                
                $perm = array();
                
                $true_false = null;
                foreach($options as $option) {
                        
                        $rand = mt_rand(0,2);
                        
                        if($rand == 0) { continue 1; }
                        
                        if(mt_rand(0,1)==0) { $true_false = false; } else { $true_false = true; }
                        if($rand == 1) { $perm[$option] = $true_false; }
                        
                        if(mt_rand(0,1)==0) { $true_false = false; } else { $true_false = true; }
                        if($rand == 2) { $perm[$option] = $true_false; }
                        
                }
                $perms[] = $perm;
        }
        
        return $perms;
        
}

function hex2bin($h) {
        if (!is_string($h))
                return null;
        $r = '';
        for ($a = 0; $a < strlen($h); $a+=2) {
                $r.=chr(hexdec($h{$a} . $h{($a + 1)}));
        }
        return $r;
}

