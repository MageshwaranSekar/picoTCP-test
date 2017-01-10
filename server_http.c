#include "pico_defines.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_dev_tap.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_https_server.h"
#include "pico_https_util.h"
#include "pico_https_glue.h"
#include "wolfssl/ssl.h"
#include "custom_memalloc.h"


#define HEAPSIZE 200000


#ifndef USE_TLS_PSK
#define PSK_SERVER_CB_ARG

const unsigned char cert_pem[]="Certificate:\n\
    Data:\n\
        Version: 3 (0x2)\n\
        Serial Number: 1 (0x1)\n\
    Signature Algorithm: sha256WithRSAEncryption\n\
        Issuer: C=US, ST=Montana, L=Bozeman, O=Sawtooth, OU=Consulting, CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
        Validity\n\
            Not Before: Aug 11 20:07:37 2016 GMT\n\
            Not After : May  8 20:07:37 2019 GMT\n\
        Subject: C=US, ST=Montana, L=Bozeman, O=wolfSSL, OU=Support, CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
        Subject Public Key Info:\n\
            Public Key Algorithm: rsaEncryption\n\
                Public-Key: (2048 bit)\n\
                Modulus:\n\
                    00:c0:95:08:e1:57:41:f2:71:6d:b7:d2:45:41:27:\n\
                    01:65:c6:45:ae:f2:bc:24:30:b8:95:ce:2f:4e:d6:\n\
                    f6:1c:88:bc:7c:9f:fb:a8:67:7f:fe:5c:9c:51:75:\n\
                    f7:8a:ca:07:e7:35:2f:8f:e1:bd:7b:c0:2f:7c:ab:\n\
                    64:a8:17:fc:ca:5d:7b:ba:e0:21:e5:72:2e:6f:2e:\n\
                    86:d8:95:73:da:ac:1b:53:b9:5f:3f:d7:19:0d:25:\n\
                    4f:e1:63:63:51:8b:0b:64:3f:ad:43:b8:a5:1c:5c:\n\
                    34:b3:ae:00:a0:63:c5:f6:7f:0b:59:68:78:73:a6:\n\
                    8c:18:a9:02:6d:af:c3:19:01:2e:b8:10:e3:c6:cc:\n\
                    40:b4:69:a3:46:33:69:87:6e:c4:bb:17:a6:f3:e8:\n\
                    dd:ad:73:bc:7b:2f:21:b5:fd:66:51:0c:bd:54:b3:\n\
                    e1:6d:5f:1c:bc:23:73:d1:09:03:89:14:d2:10:b9:\n\
                    64:c3:2a:d0:a1:96:4a:bc:e1:d4:1a:5b:c7:a0:c0:\n\
                    c1:63:78:0f:44:37:30:32:96:80:32:23:95:a1:77:\n\
                    ba:13:d2:97:73:e2:5d:25:c9:6a:0d:c3:39:60:a4:\n\
                    b4:b0:69:42:42:09:e9:d8:08:bc:33:20:b3:58:22:\n\
                    a7:aa:eb:c4:e1:e6:61:83:c5:d2:96:df:d9:d0:4f:\n\
                    ad:d7\n\
                Exponent: 65537 (0x10001)\n\
        X509v3 extensions:\n\
            X509v3 Subject Key Identifier: \n\
                B3:11:32:C9:92:98:84:E2:C9:F8:D0:3B:6E:03:42:CA:1F:0E:8E:3C\n\
            X509v3 Authority Key Identifier: \n\
                keyid:27:8E:67:11:74:C3:26:1D:3F:ED:33:63:B3:A4:D8:1D:30:E5:E8:D5\n\
                DirName:/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
                serial:B7:B6:90:33:66:1B:6B:23\n\
\n\
            X509v3 Basic Constraints: \n\
                CA:TRUE\n\
    Signature Algorithm: sha256WithRSAEncryption\n\
         51:fe:2a:df:07:7e:43:ca:66:8d:15:c4:2b:db:57:b2:06:6d:\n\
         0d:90:66:ff:a5:24:9c:14:ef:81:f2:a4:ab:99:a9:6a:49:20:\n\
         a5:d2:71:e7:1c:3c:99:07:c7:47:fc:e8:96:b4:f5:42:30:ce:\n\
         39:01:4b:d1:c2:e8:bc:95:84:87:ce:55:5d:97:9f:cf:78:f3:\n\
         56:9b:a5:08:6d:ac:f6:a5:5c:c4:ef:3e:2a:39:a6:48:26:29:\n\
         7b:2d:e0:cd:a6:8c:57:48:0b:bb:31:32:c2:bf:d9:43:4c:47:\n\
         25:18:81:a8:c9:33:82:41:9b:ba:61:86:d7:84:93:17:24:25:\n\
         36:ca:4d:63:6b:4f:95:79:d8:60:e0:1e:f5:ac:c1:8a:a1:b1:\n\
         7e:85:8e:87:20:2f:08:31:ad:5e:c6:4a:c8:61:f4:9e:07:1e:\n\
         a2:22:ed:73:7c:85:ee:fa:62:dc:50:36:aa:fd:c7:9d:aa:18:\n\
         04:fb:ea:cc:2c:68:9b:b3:a9:c2:96:d8:c1:cc:5a:7e:f7:0d:\n\
         9e:08:e0:9d:29:8b:84:46:8f:d3:91:6a:b5:b8:7a:5c:cc:4f:\n\
         55:01:b8:9a:48:a0:94:43:ca:25:47:52:0a:f7:f4:be:b0:d1:\n\
         71:6d:a5:52:4a:65:50:b2:ad:4e:1d:e0:6c:01:d8:fb:43:80:\n\
         e6:e4:0c:37\n\
-----BEGIN CERTIFICATE-----\n\
MIIEnjCCA4agAwIBAgIBATANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMCVVMx\n\
EDAOBgNVBAgMB01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4xETAPBgNVBAoMCFNh\n\
d3Rvb3RoMRMwEQYDVQQLDApDb25zdWx0aW5nMRgwFgYDVQQDDA93d3cud29sZnNz\n\
bC5jb20xHzAdBgkqhkiG9w0BCQEWEGluZm9Ad29sZnNzbC5jb20wHhcNMTYwODEx\n\
MjAwNzM3WhcNMTkwNTA4MjAwNzM3WjCBkDELMAkGA1UEBhMCVVMxEDAOBgNVBAgM\n\
B01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4xEDAOBgNVBAoMB3dvbGZTU0wxEDAO\n\
BgNVBAsMB1N1cHBvcnQxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG\n\
SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n\
ADCCAQoCggEBAMCVCOFXQfJxbbfSRUEnAWXGRa7yvCQwuJXOL07W9hyIvHyf+6hn\n\
f/5cnFF194rKB+c1L4/hvXvAL3yrZKgX/Mpde7rgIeVyLm8uhtiVc9qsG1O5Xz/X\n\
GQ0lT+FjY1GLC2Q/rUO4pRxcNLOuAKBjxfZ/C1loeHOmjBipAm2vwxkBLrgQ48bM\n\
QLRpo0YzaYduxLsXpvPo3a1zvHsvIbX9ZlEMvVSz4W1fHLwjc9EJA4kU0hC5ZMMq\n\
0KGWSrzh1Bpbx6DAwWN4D0Q3MDKWgDIjlaF3uhPSl3PiXSXJag3DOWCktLBpQkIJ\n\
6dgIvDMgs1gip6rrxOHmYYPF0pbf2dBPrdcCAwEAAaOB/DCB+TAdBgNVHQ4EFgQU\n\
sxEyyZKYhOLJ+NA7bgNCyh8OjjwwgckGA1UdIwSBwTCBvoAUJ45nEXTDJh0/7TNj\n\
s6TYHTDl6NWhgZqkgZcwgZQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5h\n\
MRAwDgYDVQQHDAdCb3plbWFuMREwDwYDVQQKDAhTYXd0b290aDETMBEGA1UECwwK\n\
Q29uc3VsdGluZzEYMBYGA1UEAwwPd3d3LndvbGZzc2wuY29tMR8wHQYJKoZIhvcN\n\
AQkBFhBpbmZvQHdvbGZzc2wuY29tggkAt7aQM2YbayMwDAYDVR0TBAUwAwEB/zAN\n\
BgkqhkiG9w0BAQsFAAOCAQEAUf4q3wd+Q8pmjRXEK9tXsgZtDZBm/6UknBTvgfKk\n\
q5mpakkgpdJx5xw8mQfHR/zolrT1QjDOOQFL0cLovJWEh85VXZefz3jzVpulCG2s\n\
9qVcxO8+KjmmSCYpey3gzaaMV0gLuzEywr/ZQ0xHJRiBqMkzgkGbumGG14STFyQl\n\
NspNY2tPlXnYYOAe9azBiqGxfoWOhyAvCDGtXsZKyGH0ngceoiLtc3yF7vpi3FA2\n\
qv3HnaoYBPvqzCxom7OpwpbYwcxafvcNngjgnSmLhEaP05Fqtbh6XMxPVQG4mkig\n\
lEPKJUdSCvf0vrDRcW2lUkplULKtTh3gbAHY+0OA5uQMNw==\n\
-----END CERTIFICATE-----\n\
Certificate:\n\
    Data:\n\
        Version: 3 (0x2)\n\
        Serial Number:\n\
            b7:b6:90:33:66:1b:6b:23\n\
    Signature Algorithm: sha256WithRSAEncryption\n\
        Issuer: C=US, ST=Montana, L=Bozeman, O=Sawtooth, OU=Consulting, CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
        Validity\n\
            Not Before: Aug 11 20:07:37 2016 GMT\n\
            Not After : May  8 20:07:37 2019 GMT\n\
        Subject: C=US, ST=Montana, L=Bozeman, O=Sawtooth, OU=Consulting, CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
        Subject Public Key Info:\n\
            Public Key Algorithm: rsaEncryption\n\
                Public-Key: (2048 bit)\n\
                Modulus:\n\
                    00:bf:0c:ca:2d:14:b2:1e:84:42:5b:cd:38:1f:4a:\n\
                    f2:4d:75:10:f1:b6:35:9f:df:ca:7d:03:98:d3:ac:\n\
                    de:03:66:ee:2a:f1:d8:b0:7d:6e:07:54:0b:10:98:\n\
                    21:4d:80:cb:12:20:e7:cc:4f:de:45:7d:c9:72:77:\n\
                    32:ea:ca:90:bb:69:52:10:03:2f:a8:f3:95:c5:f1:\n\
                    8b:62:56:1b:ef:67:6f:a4:10:41:95:ad:0a:9b:e3:\n\
                    a5:c0:b0:d2:70:76:50:30:5b:a8:e8:08:2c:7c:ed:\n\
                    a7:a2:7a:8d:38:29:1c:ac:c7:ed:f2:7c:95:b0:95:\n\
                    82:7d:49:5c:38:cd:77:25:ef:bd:80:75:53:94:3c:\n\
                    3d:ca:63:5b:9f:15:b5:d3:1d:13:2f:19:d1:3c:db:\n\
                    76:3a:cc:b8:7d:c9:e5:c2:d7:da:40:6f:d8:21:dc:\n\
                    73:1b:42:2d:53:9c:fe:1a:fc:7d:ab:7a:36:3f:98:\n\
                    de:84:7c:05:67:ce:6a:14:38:87:a9:f1:8c:b5:68:\n\
                    cb:68:7f:71:20:2b:f5:a0:63:f5:56:2f:a3:26:d2:\n\
                    b7:6f:b1:5a:17:d7:38:99:08:fe:93:58:6f:fe:c3:\n\
                    13:49:08:16:0b:a7:4d:67:00:52:31:67:23:4e:98:\n\
                    ed:51:45:1d:b9:04:d9:0b:ec:d8:28:b3:4b:bd:ed:\n\
                    36:79\n\
                Exponent: 65537 (0x10001)\n\
        X509v3 extensions:\n\
            X509v3 Subject Key Identifier: \n\
                27:8E:67:11:74:C3:26:1D:3F:ED:33:63:B3:A4:D8:1D:30:E5:E8:D5\n\
            X509v3 Authority Key Identifier: \n\
                keyid:27:8E:67:11:74:C3:26:1D:3F:ED:33:63:B3:A4:D8:1D:30:E5:E8:D5\n\
                DirName:/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
                serial:B7:B6:90:33:66:1B:6B:23\n\
\n\
            X509v3 Basic Constraints: \n\
                CA:TRUE\n\
    Signature Algorithm: sha256WithRSAEncryption\n\
         0e:93:48:44:4a:72:96:60:71:25:82:a9:2c:ca:60:5b:f2:88:\n\
         3e:cf:11:74:5a:11:4a:dc:d9:d8:f6:58:2c:05:d3:56:d9:e9:\n\
         8f:37:ef:8e:3e:3b:ff:22:36:00:ca:d8:e2:96:3f:a7:d1:ed:\n\
         1f:de:7a:b0:d7:8f:36:bd:41:55:1e:d4:b9:86:3b:87:25:69:\n\
         35:60:48:d6:e4:5a:94:ce:a2:fa:70:38:36:c4:85:b4:4b:23:\n\
         fe:71:9e:2f:db:06:c7:b5:9c:21:f0:3e:7c:eb:91:f8:5c:09:\n\
         fd:84:43:a4:b3:4e:04:0c:22:31:71:6a:48:c8:ab:bb:e8:ce:\n\
         fa:67:15:1a:3a:82:98:43:33:b5:0e:1f:1e:89:f8:37:de:1b:\n\
         e6:b5:a0:f4:a2:8b:b7:1c:90:ba:98:6d:94:21:08:80:5d:f3:\n\
         bf:66:ad:c9:72:28:7a:6a:48:ee:cf:63:69:31:8c:c5:8e:66:\n\
         da:4b:78:65:e8:03:3a:4b:f8:cc:42:54:d3:52:5c:2d:04:ae:\n\
         26:87:e1:7e:40:cb:45:41:16:4b:6e:a3:2e:4a:76:bd:29:7f:\n\
         1c:53:37:06:ad:e9:5b:6a:d6:b7:4e:94:a2:7c:e8:ac:4e:a6:\n\
         50:3e:2b:32:9e:68:42:1b:e4:59:67:61:ea:c7:9a:51:9c:1c:\n\
         55:a3:77:76\n\
-----BEGIN CERTIFICATE-----\n\
MIIEqjCCA5KgAwIBAgIJALe2kDNmG2sjMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYD\n\
VQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8G\n\
A1UECgwIU2F3dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3\n\
dy53b2xmc3NsLmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTAe\n\
Fw0xNjA4MTEyMDA3MzdaFw0xOTA1MDgyMDA3MzdaMIGUMQswCQYDVQQGEwJVUzEQ\n\
MA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8GA1UECgwIU2F3\n\
dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3dy53b2xmc3Ns\n\
LmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZI\n\
hvcNAQEBBQADggEPADCCAQoCggEBAL8Myi0Ush6EQlvNOB9K8k11EPG2NZ/fyn0D\n\
mNOs3gNm7irx2LB9bgdUCxCYIU2AyxIg58xP3kV9yXJ3MurKkLtpUhADL6jzlcXx\n\
i2JWG+9nb6QQQZWtCpvjpcCw0nB2UDBbqOgILHztp6J6jTgpHKzH7fJ8lbCVgn1J\n\
XDjNdyXvvYB1U5Q8PcpjW58VtdMdEy8Z0TzbdjrMuH3J5cLX2kBv2CHccxtCLVOc\n\
/hr8fat6Nj+Y3oR8BWfOahQ4h6nxjLVoy2h/cSAr9aBj9VYvoybSt2+xWhfXOJkI\n\
/pNYb/7DE0kIFgunTWcAUjFnI06Y7VFFHbkE2Qvs2CizS73tNnkCAwEAAaOB/DCB\n\
+TAdBgNVHQ4EFgQUJ45nEXTDJh0/7TNjs6TYHTDl6NUwgckGA1UdIwSBwTCBvoAU\n\
J45nEXTDJh0/7TNjs6TYHTDl6NWhgZqkgZcwgZQxCzAJBgNVBAYTAlVTMRAwDgYD\n\
VQQIDAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMREwDwYDVQQKDAhTYXd0b290\n\
aDETMBEGA1UECwwKQ29uc3VsdGluZzEYMBYGA1UEAwwPd3d3LndvbGZzc2wuY29t\n\
MR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tggkAt7aQM2YbayMwDAYD\n\
VR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADpNIREpylmBxJYKpLMpgW/KI\n\
Ps8RdFoRStzZ2PZYLAXTVtnpjzfvjj47/yI2AMrY4pY/p9HtH956sNePNr1BVR7U\n\
uYY7hyVpNWBI1uRalM6i+nA4NsSFtEsj/nGeL9sGx7WcIfA+fOuR+FwJ/YRDpLNO\n\
BAwiMXFqSMiru+jO+mcVGjqCmEMztQ4fHon4N94b5rWg9KKLtxyQuphtlCEIgF3z\n\
v2atyXIoempI7s9jaTGMxY5m2kt4ZegDOkv4zEJU01JcLQSuJofhfkDLRUEWS26j\n\
Lkp2vSl/HFM3Bq3pW2rWt06UonzorE6mUD4rMp5oQhvkWWdh6seaUZwcVaN3dg==\n\
-----END CERTIFICATE-----\n";


const unsigned char privkey_pem[]="-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpQIBAAKCAQEAwJUI4VdB8nFtt9JFQScBZcZFrvK8JDC4lc4vTtb2HIi8fJ/7\n\
qGd//lycUXX3isoH5zUvj+G9e8AvfKtkqBf8yl17uuAh5XIuby6G2JVz2qwbU7lf\n\
P9cZDSVP4WNjUYsLZD+tQ7ilHFw0s64AoGPF9n8LWWh4c6aMGKkCba/DGQEuuBDj\n\
xsxAtGmjRjNph27Euxem8+jdrXO8ey8htf1mUQy9VLPhbV8cvCNz0QkDiRTSELlk\n\
wyrQoZZKvOHUGlvHoMDBY3gPRDcwMpaAMiOVoXe6E9KXc+JdJclqDcM5YKS0sGlC\n\
Qgnp2Ai8MyCzWCKnquvE4eZhg8XSlt/Z0E+t1wIDAQABAoIBAQCa0DQPUmIFUAHv\n\
n+1kbsLE2hryhNeSEEiSxOlq64t1bMZ5OPLJckqGZFSVd8vDmp231B2kAMieTuTd\n\
x7pnFsF0vKnWlI8rMBr77d8hBSPZSjm9mGtlmrjcxH3upkMVLj2+HSJgKnMw1T7Y\n\
oqyGQy7E9WReP4l1DxHYUSVOn9iqo85gs+KK2X4b8GTKmlsFC1uqy+XjP24yIgXz\n\
0PrvdFKB4l90073/MYNFdfpjepcu1rYZxpIm5CgGUFAOeC6peA0Ul7QS2DFAq6EB\n\
QcIw+AdfFuRhd9Jg8p+N6PS662PeKpeB70xs5lU0USsoNPRTHMRYCj+7r7X3SoVD\n\
LTzxWFiBAoGBAPIsVHY5I2PJEDK3k62vvhl1loFk5rW4iUJB0W3QHBv4G6xpyzY8\n\
ZH3c9Bm4w2CxV0hfUk9ZOlV/MsAZQ1A/rs5vF/MOn0DKTq0VO8l56cBZOHNwnAp8\n\
yTpIMqfYSXUKhcLC/RVz2pkJKmmanwpxv7AEpox6Wm9IWlQ7xrFTF9/nAoGBAMuT\n\
3ncVXbdcXHzYkKmYLdZpDmOzo9ymzItqpKISjI57SCyySzfcBhh96v52odSh6T8N\n\
zRtfr1+elltbD6F8r7ObkNtXczrtsCNErkFPHwdCEyNMy/r0FKTV9542fFufqDzB\n\
hV900jkt/9CE3/uzIHoumxeu5roLrl9TpFLtG8SRAoGBAOyY2rvV/vlSSn0CVUlv\n\
VW5SL4SjK7OGYrNU0mNS2uOIdqDvixWl0xgUcndex6MEH54ZYrUbG57D8rUy+UzB\n\
qusMJn3UX0pRXKRFBnBEp1bA1CIUdp7YY1CJkNPiv4GVkjFBhzkaQwsYpVMfORpf\n\
H0O8h2rfbtMiAP4imHBOGhkpAoGBAIpBVihRnl/Ungs7mKNU8mxW1KrpaTOFJAza\n\
1AwtxL9PAmk4fNTm3Ezt1xYRwz4A58MmwFEC3rt1nG9WnHrzju/PisUr0toGakTJ\n\
c/5umYf4W77xfOZltU9s8MnF/xbKixsX4lg9ojerAby/QM5TjI7t7+5ZneBj5nxe\n\
9Y5L8TvBAoGATUX5QIzFW/QqGoq08hysa+kMVja3TnKW1eWK0uL/8fEYEz2GCbjY\n\
dqfJHHFSlDBD4PF4dP1hG0wJzOZoKnGtHN9DvFbbpaS+NXCkXs9P/ABVmTo9I89n\n\
WvUi+LUp0EQR6zUuRr79jhiyX6i/GTKh9dwD5nyaHwx8qbAOITc78bA=\n\
-----END RSA PRIVATE KEY-----\n";


#else
#define PSK_SERVER_CB_ARG ,my_psk_server_cb
#endif

void serverWakeup(uint16_t ev, uint16_t conn)
{
    //char *body;
    //uint32_t read = 0;

    if(ev & EV_HTTPS_CON){
        dbg("New connection received\n");
        pico_https_server_accept();

    }

    if(ev & EV_HTTPS_REQ){ /* new header received */
        char *resource;
        int method;
        dbg("Header request received\n");
        resource = pico_https_getResource(conn);
        method = pico_https_getMethod(conn);
        
        dbg("Sending data\n");
				pico_https_respond(conn, HTTPS_RESOURCE_NOT_FOUND);
				pico_https_close(conn); //test
	//TODO: how to read data ?
        /*struct Www_file *www_file;
        www_file = find_www_file(resource + 1);
        if(www_file != NULL){
            uint16_t flags;
            flags = HTTPS_RESOURCE_FOUND | HTTPS_STATIC_RESOURCE;
            if(www_file->cacheable){
                 flags = flags | HTTPS_CACHEABLE_RESOURCE;
            }
            pico_https_respond(conn, flags);
            pico_https_submitData(conn, www_file->content, (int) *www_file->filesize);
         } 
	 else { // not found
            // reject
            dbg("Rejected connection...\n");
            pico_https_respond(conn, HTTPS_RESOURCE_NOT_FOUND);
         } */

    }

    if(ev & EV_HTTPS_PROGRESS) /* submitted data was sent */
    {
        uint16_t sent, total;
        pico_https_getProgress(conn, &sent, &total);
        dbg("Chunk statistics : %d/%d sent\n", sent, total);
    }

    if(ev & EV_HTTPS_SENT) /* submitted data was fully sent */
    {
        dbg("Last chunk post !\n");
        pico_https_submitData(conn, NULL, 0); /* send the final chunk */
    }

    if(ev & EV_HTTPS_CLOSE)
    {
        dbg("Close request: %d\n", conn);
        if (conn)
            pico_https_close(conn);
        else
            dbg(">>>>>>>> Close request w/ conn=NULL!!\n");
    }

    if(ev & EV_HTTPS_ERROR)
    {
        dbg("Error on server: %d\n", conn);
        pico_https_close(conn);
    }
}
#ifdef USE_TLS_PSK
static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity, unsigned char* key,
                              unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    if (strncmp(identity, "Client_identity", 15) != 0)
        return 0;

    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return 4;
}
#endif


char ch[HEAPSIZE];
int main(){
  struct pico_ip4 ipaddr, netmask;
  struct pico_device* dev;

	init_heap(ch, HEAPSIZE);
  /* initialise the TCP stack */
  pico_stack_init();

  /* create the tap device */
  dev = pico_tap_create("tap0");  
	if (!dev)
		return -1;

  /* assign the IP address to the tap interface */
  pico_string_to_ipv4("10.0.0.2", &ipaddr.addr);
	pico_string_to_ipv4("255.255.255.0", &netmask.addr);
  pico_ipv4_link_add(dev, ipaddr, netmask);

#ifndef USE_TLS_PSK
  /* SSL/TLS related init */
	pico_https_setCertificate(cert_pem, sizeof(cert_pem));
  pico_https_setPrivateKey(privkey_pem, sizeof(privkey_pem));
#endif

  /* start the server */ 
	if(pico_https_server_start(443, serverWakeup PSK_SERVER_CB_ARG)== HTTPS_RETURN_ERROR){
			dbg("Error in pico_https_server_start\n");
			return -1;
	}

	for (;;) {
		pico_stack_tick();
    PICO_IDLE();
	}

	return 0;

	
}





