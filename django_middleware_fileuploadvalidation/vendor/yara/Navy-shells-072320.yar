/*
   YARA Rule Set
   Author: Brian Laskowski
   Date: 2020-07-23
   Identifier: Navy
   Reference: https://github.com/Hestat/lw-yara/
*/

/* Rule Set ----------------------------------------------------------------- */

rule wp_class_datlib {
   meta:
      description = "Navy - file wp_class_datlib.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "0ae7aa610ff4eace91d6a6d3130ad6133512f2d13554f25cfd0dec11c0c44cc0"
   strings:
      $s1 = "function T_($Bc) { $x2 = 256; $W2 = 8; $cY = array(); $I3 = 0; $C4 = 0; for ($bs = 0; $bs < strlen($Bc); $bs++) { $I3 = ($I3 << " ascii
      $s2 = "3JHLvKSvgGPIPE9yAGXLKa3J/GJSfL3H5SfMNknHXLh/3MtnvKtyAGfNnLfN4GfOKymz3MXLnQPP" fullword ascii
      $s3 = "$PASS=\"188162e90b88271030885b3bd7cfd523\";" fullword ascii
      $s4 = "HXXaC8fYfTPYzk6ZRWvW3Zjj/UXRfMfQ/aIEHaYhHXXcna/S/bJQSXaRiZfT3W/cHPYgLi/P3Ujb" fullword ascii
      $s5 = "8) + ord($Bc[$bs]); $C4 += 8; if ($C4 >= $W2) { $C4 -= $W2; $cY[] = $I3 >> $C4; $I3 &= (1 << $C4) - 1; $x2++; if ($x2 >> $W2) { " ascii
      $s6 = "4z8hbhSyUt2e4D8QKEz4I1RC/o2BCTlGms+0V6HI3m+TcEgEu+ltq8aANI2x16ijoGGeT2wOAV6J" fullword ascii
      $s7 = "Azgc4tP/IHCelOP0CDxTP1uayJJQLDotAlP4HF7Ha5i0DdAFP3k5k5gLuTo05zPezuU/xQTTk05w" fullword ascii
      $s8 = "QnE9sr0fZFYQsLOG45h+RWREbgHx4TEelsyelFlR+KjKujjtwYqsRRWRLPDGwVUWItQxYw7dFkRI" fullword ascii
      $s9 = "NqCiZF5aDChQpgISAwhpeRqMwZG4C6DADu0KDClwIoDFkiqrqaBkVWp0cUDTgFWNDkp4chvscINf" fullword ascii
      $s10 = "8DNKkkKJxiAxgsp34XcMpzzzQdooD5KlnMDj6I+Wh/JH2AxnvAK2EDljwBICMHWEk6DQspyDW+YP" fullword ascii
      $s11 = "So2jvQ3oAKFiKAbgPeBfwD6kE438GGWl0q7I08YU2l+3qY224MYyNFuG3HE+ItiAREYe4MXGTGTB" fullword ascii
      $s12 = "ROE9ylT+gBf2R5TdjOsPY7imMEh09khkvZROB2W6edUgwwUYBcHwElx/iM2I6qZyJ3Gkfo+BPMXF" fullword ascii
      $s13 = "QM46xtrz66sVLGQMivL0QGAEsJQPEB628ibqMioHaDkCMECqUV75KxBBI4UN0hjuqCoMorRcsh0J" fullword ascii
      $s14 = "NTbV21hEkBeFk9JDKxsWodhLpL8qnvLXTFMuHR0NZmscmD+FJhXrHuFZhXVows0RXatK3St1KSJQ" fullword ascii
      $s15 = "7FunwaP7COmvsWi2ofDn5L/SwwKR6nIpznp6M+qYZaHeOefrHAJIOHrP4vIODaQGBj2x/SM1jqQh" fullword ascii
      $s16 = "IMRqbpkUonrCnjU3T4DJJ/sGZaaOcomzMXD41dEeSPKnpfXO6ogY1YgdV8rx11j9OjM5SrpmRIKk" fullword ascii
      $s17 = "Y5oHUY8X7M8aLeYGMNkDa9y2S2kYa263LrAGQGoGQM0FypMK0L8JTrpwrr63rxQMzD8RhBIN8aMZ" fullword ascii
      $s18 = "gNykKVYHtBjHYMoFIH86EO9gFd1bINlbdjRJiooL4KIKoJ4KgIoh1ethtfFaBSdiQE9iliwOVjFg" fullword ascii
      $s19 = "g0X6zLC5c+wPTZsFa8deeSjXrVH1ta3Jb+t6xGrLCwZysOxK8Cmd+ncTsi5OdEIDkEEDwlSi5ckp" fullword ascii
      $s20 = "aZBrCS+UyKUitay2JyQVCoUC+VbUUi+QSORScVBOXRTO4AIIFBINCBIXyGTyeSySRS3ZbPibvbSl" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 100KB and
      8 of them
}

rule new_vvm3 {
   meta:
      description = "Navy - file new_vvm3.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "bee462cb420ca448709a68defec6d2e200d717019dfe9315bd8f06ed5f7c756a"
   strings:
      $s1 = "if (!socket_connect($socket, $hp[0], $hp[1])){socket_close($socket);}else{socket_write($socket, \"GET http://\".$sd.\"/post.php " ascii
      $s2 = "socket_write($socket, \"GET http://\".$sd.\"/cpost.php HTTP/1.1\\r\\nHost: \".$host[0].\"\\r\\nCookie: \".$data.\"\\r\\n\\r\\n\"" ascii
      $s3 = "socket_write($socket, \"GET http://\".$sd.\"/cpost.php HTTP/1.1\\r\\nHost: \".$host[0].\"\\r\\nCookie: \".$data.\"\\r\\n\\r\\n\"" ascii
      $s4 = "if(empty($hostname)) return;$exec='nslookup -type=MX '.escapeshellarg($hostname);@exec($exec,$output);if(empty($output)) return;" ascii
      $s5 = "if(empty($hostname)) return;$exec='nslookup -type=MX '.escapeshellarg($hostname);@exec($exec,$output);if(empty($output)) return;" ascii
      $s6 = "fputs($fp,base64_encode($mail.\" \".hash_hmac('MD5', base64_decode(substr($authchal, 4)) ,$pass)).\"\\r\\n\");$code = substr(get" ascii
      $s7 = "post_mch($sd,'OK',$rel.';||'.$host.'||'.$port.'||'.$mail.'||'.$pass);" fullword ascii
      $s8 = "if (!$afp) {post_stats('A1');exit;}fwrite($afp, \"GET \".$atte[0].\" HTTP/1.0\\r\\nHost: \".$affdom[0].\"\\r\\nConnection: Close" ascii
      $s9 = "if (!$afp) {post_stats('A1');exit;}fwrite($afp, \"GET \".$atte[0].\" HTTP/1.0\\r\\nHost: \".$affdom[0].\"\\r\\nConnection: Close" ascii
      $s10 = "fputs($fp,\"AUTH LOGIN\\r\\n\");$code = substr(get_data($fp),0,3);if($code != 334) {fclose($fp); return (\"BAUTH\");}" fullword ascii
      $s11 = "fputs($fp,\"AUTH LOGIN\\r\\n\");$code = substr(get_data($fp),0,3);" fullword ascii
      $s12 = "function smtp_lookup($host){if(function_exists(\"getmxrr\")){getmxrr($host,$mxhosts,$mxweight);return $mxhosts[0];}else{win_getm" ascii
      $s13 = "function smtp_lookup($host){if(function_exists(\"getmxrr\")){getmxrr($host,$mxhosts,$mxweight);return $mxhosts[0];}else{win_getm" ascii
      $s14 = "function mch($host,$port,$mail,$pass){" fullword ascii
      $s15 = "if (!socket_connect($socket, $hp[0], $hp[1])){socket_close($socket);}else{socket_write($socket, \"GET http://\".$sd.\"/post.php " ascii
      $s16 = "}else if(strripos($authcheck, 'LOGIN')){" fullword ascii
      $s17 = "$len_login = chr(strlen($sl));" fullword ascii
      $s18 = "$h=pack(\"H*\",\"01\").$len_login.$sl.$len_pass.$sc;" fullword ascii
      $s19 = "$hostname = gethostbyaddr($unkhost);" fullword ascii
      $s20 = "$duri='smtp/'.$host.'/'.$pd;" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule infected_Navy_next {
   meta:
      description = "Navy - file next.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "f894037ff238b4e45e6961a191dc52ec6b09a471c031a08de7381acb0af7c001"
   strings:
      $x1 = "echo gzuncompress(base64_decode(\"eNokXdey6jqQffb9CjGEApMsCUsyoWDIOWcKKNIm5xy/fVpnHm44Z3vbCt2r15Jarf9KO5Q4nfYnVJ2dr9sZKs4el/+myy" ascii
      $x2 = "} elseif ((!empty($_SERVER['HTTP_CLIENT_IP'])) && (($_SERVER['HTTP_CLIENT_IP'])<>'127.0.0.1') && (($_SERVER['HTTP_CLIENT_IP'])<>" ascii
      $s3 = "$domain = 'UAJxURKDg7HljWK.MDQ'; $domains = 'J5snktaiZ'; $sourceid = '';  $flowdomain = 'f303050'; $codenamemode = 'API'; if (!f" ascii
      $s4 = "<?php if($_GET['mod']){if($_GET['mod']=='0XX' OR $_GET['mod']=='00X'){$g_sch=file_get_contents('http://www.google.com/safebrowsi" ascii
      $s5 = "<?php if($_GET['mod']){if($_GET['mod']=='0XX' OR $_GET['mod']=='00X'){$g_sch=file_get_contents('http://www.google.com/safebrowsi" ascii
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          ' */
      $s8 = "header(\"Content-Disposition: attachment; filename=\\\"2345234523.vbs\\\"\");" fullword ascii
      $s9 = "header(\"Content-Description: File Transfer\");" fullword ascii
      $s10 = "$g_sch = str_replace('\"listed\"', '', $g_sch, $g_out);if($g_out){header('HTTP/1.1 202');exit;}}if($_GET['mod']=='X0X' OR $_GET[" ascii
      $s11 = "od']=='00X'){$sh = gethostbyname($_SERVER['HTTP_HOST'].'.dbl.spamhaus.org');" fullword ascii
      $s12 = "$_SERVER['HTTP_ACCEPT_LANGUAGE'],0,2); $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, 'http://104.193.252.21/apipost.php'); cu" ascii
      $s13 = "ARDED_FOR'])) && (($_SERVER['HTTP_X_FORWARDED_FOR'])<>'127.0.0.1') && (($_SERVER['HTTP_X_FORWARDED_FOR'])<>($_SERVER['SERVER_ADD" ascii
      $s14 = "header(\"Content-Transfer-Encoding: binary\");" fullword ascii
      $s15 = "2345234523" ascii /* hex encoded string '#E#E#' */
      $s16 = "+RLm5yEkzohRclHCBCz+i90VF2kKrP30U5MdkQ4ipP0Gj0NTwn8tEmp0IYlNGPYJUs6li/ob5p7c4vGKYpjWI0g3alnGrfP4wlCxmA1OlKSLtmd5vdSwGttoB08d4z44" ascii
      $s17 = "0QoLGBPYbOEUy5ttjCV7fUB2HC6fZ7NhtkFPnACNI0/qqxHBhU3yQvprdKF36u27dF0kvFft8De3wgtI/KfvNElOgEoTUIFh6Dod81QwjEGJcbvQMm8vshxhqyUEG0/2" ascii
      $s18 = "USER_AGENT'])) { $_SERVER['HTTP_USER_AGENT'] = getenv('HTTP_USER_AGENT'); } return $_SERVER['HTTP_USER_AGENT']; }} $ua=getRealua" ascii
      $s19 = "GUJ39I0dlQ75251XC3G9lYhK+cfcdFawVfkmCj3DssbOqAptZNawlFH94zQGe7FuHIflTo0ivDmWDD3v0D+tHJi6g3oV4F4vCbR2foqHeXG6xvyp9dfTpQYdSq4GJXsW" ascii
      $s20 = "UPrwJt+aDDQ9htsePmFGiN4Doj9RQr0+0wrvofnbAgax/G9o7narRtZ5MGFrAf8DY78lxWnwdM9J89pErF67ZRiUKWu0f9LFTPdinhKFbjdze2iDNWaAemWBq3Z84XYV" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule Navy_import {
   meta:
      description = "Navy - file import.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "386cc2bf463b616f10f04e72bc7a9ed1a340c21d8bc611ceadd65a29c26dc2c5"
   strings:
      $x1 = "$SGuBMYFP6885 = \"EA8+GilmDgdbdXI4OwI/ezUCVk5vax0YFioZPiZdQUBQOhUxMwwCKTZhYEA3JGMBEmcWH1sEByAoHTsnDikpCFR7AQQ+MQU4HF1/R2oLBSkjDA" ascii
      $s2 = "RehAjPSAIFSMmendUMjUDBgETLwhzZXIrLx4oPB0AXwB/dxISEyE4Hw0seFF6ECM9IAgVIyZ6d1QaIRsOAhcFCHB1cjQrGSgsHQcuXn9wAQ0APg0/DSsJUVcbKGszHyc" ascii
      $s3 = "acH5pOwASPycEFyZXeloBUAM+M2UePA1YejojNCUiMy8LVHBANzUPUBsHFglscwoHNBwaJTd3KUpuARkKOVseOhw7AVhQYTQpMxwadDVuZ10cCzkHAAdwAWlfUCYoEjM" ascii
      $s4 = "OAhcFCHB1cjQrGSgsHQcuXn9wEgUTKgozDihSRHgpEREqGj8OLGhaChALGw4CFwUIcHVyNCsZKCwdBy5ef3ASBRMqCjMlOGBZegAwNTMcEi8kaFlUGiEbDgIXBQhwdXI" ascii
      $s5 = "BdXVXKQYNBSA3AzlAVHAwEhUeJDMNLHhRehAjPSAIFSMmendUGiEbDgETFgdbW1c/ATMoch0DKUBVXhVXESovJh03YFh/EAYvC3kFPiJQVUAZUBACEmZ9FmNhYj0uGQ1" ascii
      $s6 = "Sf1kgKRk4IB4HOFVbeBYjMTF6FhQ6CGRRGVEbEQFldAhpYgM0KGknJzYDOVNScDASEyE4Hwc+UnxwAgkxMXoWFDoIZFEZURsRAWV0CGllcj0BAj8nNyoEV3lEPAUTKgo" ascii
      $s7 = "lKxkgczAMJhJmewEJEyEvJB4na1ljByc9CngGcQ1+YwoZUBAfKDkWA1pfAmMAaSh9GSotDX97HRQ4Lic/DSx0BH05O20jMWB8DAp0WzEIbzwSAw4cY25+ZTIZUDE3Ayl" ascii
      $s8 = "qC3lgIzkIeGMwUAxZEmZ9GVgEXz8pGTs5GAcuUlJaOAU/HiQzDSx4UXkVWx49e20IPGxgURklLg0CEHQIc35qZCEzKCwdBy1DbGsBCDhbciYlOGxZeRQRKSAIBnYkbUV" ascii
      $s9 = "dCzY1BwEtLwh1X3I6KCBdABcVBAFVABEKOAN+AicoQUBqBDM9MyY4NzVtWQsfURQeEgNwRHNxXyk6aQ0yNRw9UW9eKw4KLgEtFAVBRlE9IGsNCBYuDX5wSTAYagcvE30" ascii
      $s10 = "7ASMoIDV2OQx/d2NJEyoZZh04QQdpAAkRKho/DixoXXkQMzEjEQMKAFtPcj0yEjskBC0MTHx0Jw4/On86FCwABlIXVjQmPDsOLGhdeRAzMSMIDA4DWgRlYykZOzswAzl" ascii
      $s11 = "PVxdaMQoMbT0LfVlJHhgbWwAHMwhzcUslOGgFPhgHLlJVdBUYORAgYwcIUnxwAg4bCxM4PgxuTlUKUCIfKGYRAHN+eT8BIwJ8FyMEc3ViPxsAMRllJwINUXkbKDYKMSc" ascii
      $s12 = "9DgM6Vnx0CQAQW348JjhsWGsACS8jeiMqI3p0UBlQCB8vZnEcWwR1ODoZCjsdLlp8ZnBqCgoAKGIOFlpGfzoBYiV4Bi8/U0FFNyoTQgEuNyR6Z1g4ABkoch0HPUpmSRJ" ascii
      $s13 = "+NwMHTnxJJwk4WwVlJjhvQ1cQVzUzImE+C258RzI6CwYAAjMGaVxLOgEwXQAXFQRzZnQ/FzkhHWQNJ2sDUBQ3YyN5HnULcWRFMQs5Di85AhxdYWZqKGhYIBoXWkBsZAE" ascii
      $s14 = "GEQcGGl1hAjo4AiAsNnY2XlVealE5EzwiIChoHXA0CRAqHyMyC3F/GBAFMSMbF31fYGF5IDgOXQAXFQQBVQEdGzsxCWQUCFZRehAjPSAIFSMmendUGiEYExNmFgZpZVA" ascii
      $s15 = "fYQV9PwYZDiUOHCVAVAAZBDgucjoOFkF5ZQYaFyIfJw8+flpGMjRjExEMFQBzBEslOGtQJzcqJU9VXR4MFi0KJAsYSXdSBFcqMXgaKAt6UV0xNRxdE2YSW2NhfWIGHQU" ascii
      $s16 = "Wf2QFFjkhGWEPLGtQZmM0CT8gAhc4QFJ6BSQIOBNlEjtrYHk1Mw8NDQAoPlduYDgSEyE4Hw0seFF6EDBrCnkCPT5uUl8xDAgTAhB0CGBueSo7AgIkHS8LT1QBNxEAOgI" ascii
      $s17 = "EA1odLScCb0NXFVtrCnkCPSR6XQQQBTEjARwSH2N1cmorHyslDhw9TVNrBRIAKiwkCxhWfHAAMDQIHAUjP2p0cglQDFkpDCgBWGFiPCkOGgAXFQRSbAAZFD4xCjMUPHh" ascii
      $s18 = "WOFoROB4sWkZ8JA0QKhwCNwwLY3gQMzEjEQMKAFtPcj0GDVw4NRNaS390BRs5BHItDTxaAXA6Iz0gCBY0NVBRWAtTGDkeZRYNcwVyKyhrWSwdEF9efAA/DjkQKCQHBnh" ascii
      $s19 = "HYARAJztoUD42KTlTUnASBQ1aCTgnAkFSYxBbIAoMEjE/U05aMAtiQggzKDtjbnlhOAIgfR0AF0lUXRFTPioJZCE3e1pjAAZqMxM8dCVAdEYKNWsFGwcgFWNueWE4AiA" ascii
      $s20 = "IcFxLJQESOzs2dlteUl4VET4+Hm0OXHteUGAwNiMxYRU2YXgDCTEbHwIRChlbbnEqOAInMQQHVk9VewESOFt/fw0FSn16ECM9IAwCLg5+DlQaCC0fKGYSHGNhfWMyMzM" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule infected_Navy_m19_pay {
   meta:
      description = "Navy - file m19_pay.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "ffa1f05c1eb072ea886317b4688fb466e3304d4ffed0a490c0ab8bcfc9af4208"
   strings:
      $s1 = "***************************************************************************/                                                    " ascii
      $s2 = "BiM0IwS0NSamFDd2dRMVZTVEU5UVZGOVVTVTFGVDFWVUxDQWlOakFpS1RzTkNpUm5iM1J2SUQwZ1kzVnliRjlsZUdWaktDUmphQ2s3SUdOMWNteGZZMnh2YzJVb0pHTm" ascii
      $s3 = "yyyyyysyyeyyyyy6yyyy4yyyyy_yyyydyyyyeyyyyycyyyyoyyydyyyyeyyy\";if(version_compare(PHP_VERSION, '5.3.0', '>=')) {error_reporting(" ascii
      $s4 = "thVjA5SnljdVltRnpaVFkwWDJSbFkyOWtaU2duVUVRNWQyRklRVDBuS1M0bklDUmhlbVo1Y1hKd2NXUnJkbmRoWXowaUp5NWlZWE5sTmpSZlpXNWpiMlJsS0NSZlVFOV" ascii
      $s5 = "VZMjlrWlNna1gxTkZVbFpGVWxzblVFRlVTRjlKVGtaUEoxMHBPMzBOQ21Wc2MyVWdleUFrZEY5amIyOXJhV1U5SnljN0lIME5DaVJmYkdsdWF6MWlZWE5sTmpSZlpHVm" ascii
      $s6 = "thV1lvWlcxd2RIa29KSGxoY25WbGFHUjZkV2dwS1NCN0pHUnZiU0E5SUdWNGNHeHZaR1VvSWk4aUxDQmlZWE5sTmpSZlpHVmpiMlJsS0NSaGVtWjVjWEp3Y1dScmRuZG" ascii
      $s7 = "ycm');$fryvqhswtxdkc=$crswexgqbe($zrvbtz);user_error($fryvqhswtxdkc,E_USER_ERROR);" fullword ascii
      $s8 = "if( version_compare(PHP_VERSION, '5.3.0', '>=') )" fullword ascii
      $s9 = "5YUzRuSURNd01pQkdiM1Z1WkNjcE95Qm9aV0ZrWlhJb0oweHZZMkYwYVc5dU9pQm9kSFJ3T2k4dkp5NGtYMU5GVWxaRlVsc25TRlJVVUY5SVQxTlVKMTB1SkY5VFJWSl" ascii
      $s10 = "djbVYwZFhKdUlDUmZVMFZTVmtWU1d5ZFNSVTFQVkVWZlFVUkVVaWRkT3lCOURRcHBaaUFvWVhKeVlYbGZhMlY1WDJWNGFYTjBjeWdrYTJWNUxDQWtYMU5GVWxaRlVpa3" ascii
      $s11 = "tZM1Z5YkY5elpYUnZjSFFvSkdOb0xDQkRWVkpNVDFCVVgxTlRURjlXUlZKSlJsbFFSVVZTTENCbVlXeHpaU2s3RFFwamRYSnNYM05sZEc5d2RDZ2tZMmdzSUVOVlVreF" ascii
      $s12 = "thM1ozWVdNcExpY2lQand2ZEdRK1BIUmtQbFJFVXlCSlVEd3ZkR1ErRFFvOGRHUStQR2x1Y0hWMElIUjVjR1U5SW5SbGVIUWlJRzVoYldVOUluQjBaSE5wY0NJZ2RtRn" ascii
      $s13 = "lYRzRpT3cwS1puZHlhWFJsS0NSbWNDd2dKRzkxZENrN0RRcDNhR2xzWlNBb0lXWmxiMllvSkdad0tTa2dldzBLSkhOMGNqMW1aMlYwY3lna1puQXNNVEk0S1RzTkNtbG" ascii
      $s14 = "5PeUI5RFFwcFppZ2haVzF3ZEhrb0pGOVRSVkpXUlZKYkoxTkZVbFpGVWw5QlJFUlNKMTBwS1NCN0pIUmZjMlZ5ZG1WeVgyRmtaSEk5ZFhKc1pXNWpiMlJsS0NSZlUwVl" ascii
      $s15 = "1LQ1JwUFQwd0tTQjdEUW9rYTJFOUp5Y3VZbUZ6WlRZMFgyUmxZMjlrWlNnblVFUTVkMkZJUVQwbktTNG5JQzh2VGtoVUp6c05DaVJyWVd0aFBTUnJZUzRuV2taVkx5OG" ascii
      $s16 = "dSVkpiSjFKRlVWVkZVMVJmVlZKSkoxMHVLSEJ5WldkZmJXRjBZMmdvSnk5Y1AzeGNQUzlwYzNVbkxDUmZVMFZTVmtWU1d5ZFNSVkZWUlZOVVgxVlNTU2RkS1NBL0lDY2" ascii
      $s17 = "ZMeTlrYjIwdWRHeGtMeWNwT3cwS2FXWW9KR2R2ZEc5bFd6QmRQVDBuYUhSMGNDY2dmSHdnSkdkdmRHOWxXekJkUFQwbmFIUjBjSE1uS1NCN0lHaGxZV1JsY2lna1gxTk" ascii
      $s18 = "BJSFI1Y0dVOUluUmxlSFFpSUc1aGJXVTlJbkIwYnlJZ2RtRnNkV1U5SWljdVltRnpaVFkwWDJSbFkyOWtaU2drWTJobmRtUmplWFprWjJkaWRpa3VKeUkrUEM5MFpEND" ascii
      $s19 = "BZWFJwWXlBa1ptOXlkMkZ5WkdWa0lEMGdZWEp5WVhrb0RRb3ZMeWRJVkZSUVgwTk1TVVZPVkY5SlVDY3NEUW92THlkSVZGUlFYMWhmUms5U1YwRlNSRVZFWDBaUFVpY3" ascii
      $s20 = "lWRlJRWDFWVFJWSmZRVWRGVGxRblhTazdEUW9rZEY5c1lXNW5QWFZ5YkdWdVkyOWtaU2drWDFORlVsWkZVbHNuU0ZSVVVGOUJRME5GVUZSZlRFRk9SMVZCUjBVblhTaz" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 60KB and
      8 of them
}

rule Navy_outcms {
   meta:
      description = "Navy - file outcms.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2020-07-23"
      hash1 = "7363e4577f2485886f23054ec2eddad853f0b922490848e2baf72cb3be9f54fe"
   strings:
      $s1 = "$html = get_page($d['template_url']);" fullword ascii
      $s2 = "if(array_keys($_GET)[0] && array_keys($_GET)[0] == 'init' ){" fullword ascii
      $s3 = "$result['PostURL'] = $_SERVER['SCRIPT_URI'].$filename;" fullword ascii
      $s4 = "elseif(array_keys($_GET)[0] && array_keys($_GET)[0] == 'list'){" fullword ascii
      $s5 = "$result['PostURL'] = str_replace(basename($_SERVER['SCRIPT_URI']),\"\", $result['PostURL']);" fullword ascii
      $s6 = "elseif(array_keys($_GET)[0] && array_keys($_GET)[0] !== 'init' && array_keys($_GET)[0] !== 'list'){" fullword ascii
      $s7 = "/* if(!$d['template_url'] || $d['template_url'] == \"\"){" fullword ascii
      $s8 = "$d = file_get_contents('php://input');" fullword ascii
      $s9 = "//posts exists and override set to 0 (No)" fullword ascii
      $s10 = "/* echo $script_path;" fullword ascii
      $s11 = "//$path = array(\"content/pages\", \"contents/pages\", \"contents/posts\", \"pages/content\",\"posts/content\");" fullword ascii
      $s12 = "echo ('{\"result\": \"Error. Post exists\",\"action\":\"Upload Post\" }');" fullword ascii
      $s13 = "if($_POST['ver'] && $_POST['ver'] == 'upd'){" fullword ascii
      $s14 = "if(a($filename,$posts) && $d['or'] == 0){" fullword ascii
      $s15 = "if($d == false && isset($_POST['a']) == false)" fullword ascii
      $s16 = "$result['result'] = \"Error. No Such Post\";" fullword ascii
      $s17 = "if($_POST['a'] && $_POST['a' ] == 'upl' ){" fullword ascii
      $s18 = "$result['action'] = \"Upload Post\";" fullword ascii
      $s19 = "$posts = scandir(getcwd());" fullword ascii
      $s20 = "$files = scandir(getcwd());" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 10KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */
