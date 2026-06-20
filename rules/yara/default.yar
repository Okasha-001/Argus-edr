// ARGUS bundled YARA signatures.
//
// These scan the bytes of executed files (process.executable) and raise R-0073
// on any hit. The agent scans the binary that is exec'd, so signatures here
// target malicious *binaries* (miners, dropped ELFs, reverse-shell tools), not
// interpreted scripts. Keep them high-confidence: R-0073 alerts on any match.

rule EICAR_Test_File {
    meta:
        description = "EICAR standard antivirus test file"
        reference   = "https://www.eicar.org"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Linux_CoinMiner {
    meta:
        description = "Cryptocurrency miner indicators (XMRig / cryptonight / stratum)"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "--donate-level"
        $c = "cryptonight" nocase
        $d = "xmrig" nocase
    condition:
        2 of them
}

rule Linux_Reverse_Shell_Binary {
    meta:
        description = "Binary embedding an interactive shell wired to a network socket"
    strings:
        $sh1  = "/bin/sh -i"
        $sh2  = "/bin/bash -i"
        $tcp  = "/dev/tcp/"
        $sock = "socket"
        $dup  = "dup2"
    condition:
        ($sh1 or $sh2) and ($tcp or ($sock and $dup))
}

rule PHP_Webshell {
    meta:
        description = "PHP webshell running request-controlled input (matches a .php run directly)"
    strings:
        $php  = "<?php"
        $sys  = "system(" nocase
        $exec = "shell_exec(" nocase
        $pass = "$_POST"
        $get  = "$_GET"
        $req  = "$_REQUEST"
    condition:
        $php and ($sys or $exec) and ($pass or $get or $req)
}
