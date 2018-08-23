import fsb795

#Строка с сертификатом в формате PEM
certpem = """
-----BEGIN CERTIFICATE-----
MIIG3DCCBougAwIBAgIKE8/KkAAAAAAC4zAIBgYqhQMCAgMwggFKMR4wHAYJKoZI
hvcNAQkBFg9kaXRAbWluc3Z5YXoucnUxCzAJBgNVBAYTAlJVMRwwGgYDVQQIDBM3
NyDQsy4g0JzQvtGB0LrQstCwMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxPzA9BgNV
BAkMNjEyNTM3NSDQsy4g0JzQvtGB0LrQstCwLCDRg9C7LiDQotCy0LXRgNGB0LrQ
sNGPLCDQtC4gNzEsMCoGA1UECgwj0JzQuNC90LrQvtC80YHQstGP0LfRjCDQoNC+
0YHRgdC40LgxGDAWBgUqhQNkARINMTA0NzcwMjAyNjcwMTEaMBgGCCqFAwOBAwEB
EgwwMDc3MTA0NzQzNzUxQTA/BgNVBAMMONCT0L7Qu9C+0LLQvdC+0Lkg0YPQtNC+
0YHRgtC+0LLQtdGA0Y/RjtGJ0LjQuSDRhtC10L3RgtGAMB4XDTE4MDcwOTE1MjYy
NFoXDTI3MDcwOTE1MjYyNFowggFVMR4wHAYJKoZIhvcNAQkBFg9jb250YWN0QGVr
ZXkucnUxITAfBgNVBAMMGNCe0J7QniDCq9CV0LrQtdC5INCj0KbCuzEwMC4GA1UE
Cwwn0KPQtNC+0YHRgtC+0LLQtdGA0Y/RjtGJ0LjQuSDRhtC10L3RgtGAMSEwHwYD
VQQKDBjQntCe0J4gwqvQldC60LXQuSDQo9CmwrsxCzAJBgNVBAYTAlJVMRgwFgYD
VQQIDA83NyDQnNC+0YHQutCy0LAxRDBCBgNVBAkMO9Cj0JvQmNCm0JAg0JjQm9Cs
0JjQndCa0JAsINCULjQsINCQ0J3QotCgIDMg0K3Qojsg0J/QntCcLjk0MRgwFgYD
VQQHDA/Qsy7QnNC+0YHQutCy0LAxGDAWBgUqhQNkARINMTE0Nzc0NjcxNDYzMTEa
MBgGCCqFAwOBAwEBEgwwMDc3MTA5NjQzNDgwYzAcBgYqhQMCAhMwEgYHKoUDAgIk
AAYHKoUDAgIeAQNDAARAW3hfhvDdUxa6N8hEDjmOg/LsDDRHj5DanAyARtNB/2b5
BEzQCg4lUwrO/VHmvoUtvsrLqrxV6Ae+jh+GFli9WKOCA0AwggM8MBIGA1UdEwEB
/wQIMAYBAf8CAQAwHQYDVR0OBBYEFMQYnG5GfYRnj2ehEQ5tv8Fso/qBMAsGA1Ud
DwQEAwIBRjAdBgNVHSAEFjAUMAgGBiqFA2RxATAIBgYqhQNkcQIwKAYFKoUDZG8E
Hwwd0KHQmtCX0JggwqvQm9CY0KDQodCh0JstQ1NQwrswggGLBgNVHSMEggGCMIIB
foAUi5g7iRhR6O+cAni46sjUILJVyV2hggFSpIIBTjCCAUoxHjAcBgkqhkiG9w0B
CQEWD2RpdEBtaW5zdnlhei5ydTELMAkGA1UEBhMCUlUxHDAaBgNVBAgMEzc3INCz
LiDQnNC+0YHQutCy0LAxFTATBgNVBAcMDNCc0L7RgdC60LLQsDE/MD0GA1UECQw2
MTI1Mzc1INCzLiDQnNC+0YHQutCy0LAsINGD0LsuINCi0LLQtdGA0YHQutCw0Y8s
INC0LiA3MSwwKgYDVQQKDCPQnNC40L3QutC+0LzRgdCy0Y/Qt9GMINCg0L7RgdGB
0LjQuDEYMBYGBSqFA2QBEg0xMDQ3NzAyMDI2NzAxMRowGAYIKoUDA4EDAQESDDAw
NzcxMDQ3NDM3NTFBMD8GA1UEAww40JPQvtC70L7QstC90L7QuSDRg9C00L7RgdGC
0L7QstC10YDRj9GO0YnQuNC5INGG0LXQvdGC0YCCEDRoHkDLQe8zqaC3yHaSmikw
WQYDVR0fBFIwUDAmoCSgIoYgaHR0cDovL3Jvc3RlbGVjb20ucnUvY2RwL2d1Yy5j
cmwwJqAkoCKGIGh0dHA6Ly9yZWVzdHItcGtpLnJ1L2NkcC9ndWMuY3JsMIHGBgUq
hQNkcASBvDCBuQwj0J/QkNCa0JwgwqvQmtGA0LjQv9GC0L7Qn9GA0L4gSFNNwrsM
INCf0JDQmiDCq9CT0L7Qu9C+0LLQvdC+0Lkg0KPQpsK7DDbQl9Cw0LrQu9GO0YfQ
tdC90LjQtSDihJYgMTQ5LzMvMi8yLTk5OSDQvtGCIDA1LjA3LjIwMTIMONCX0LDQ
utC70Y7Rh9C10L3QuNC1IOKEliAxNDkvNy8xLzQvMi02MDMg0L7RgiAwNi4wNy4y
MDEyMAgGBiqFAwICAwNBALvjFGhdFE9llvlvKeQmZmkI5J+yO2jFWTh8nXPjIpiL
OutUew2hIZv15pJ1QM/VgRO3BTBGDOoIrq8LvgC+3kA=
-----END CERTIFICATE-----
"""
#Сертификат формата PEM/DER из файла
#c1 = fsb795.Certificate('OOO_VOLGA.der')
#c1 = fsb795.Certificate('cert.pem')
#Сертификат формата PEM из строки 
c1 = fsb795.Certificate(certpem)
if (c1.pyver == ''):
    print('Context for certificate not create')
    exit(-1)
print('=================formatCert================================')
print(c1.formatCert)
res = c1.subjectSignTool()
print('=================subjectSignTool================================')
print (res)
print('=================issuerSignTool================================')
res1 = c1.issuerSignTool()
print (res1[0])
print (res1[1])
print (res1[2])
print (res1[3])
print('=================prettyPrint================================')
res2 = c1.prettyPrint()
#print(res2)
print('=================classUser================================')
res3 = c1.classUser()
print (res3)
print('=================issuerCert================================')
iss, vlad_is = c1.issuerCert()
print ('vlad_is=' + str(vlad_is))
for key in iss.keys():
    print (key + '=' + iss[key])
print('=================subjectCert================================')
sub, vlad_sub = c1.subjectCert()
print ('vlad_sub=' + str(vlad_sub))
for key in sub.keys():
    print (key + '=' + sub[key])
print('================publicKey=================================')
key_info = c1.publicKey()
print(key_info['curve'])
print(key_info['hash'])
print(key_info['valuepk'])
print('================serialNumber=================================')
print(c1.serialNumber())
print('================validityCert=================================')
valid = c1.validityCert()
print(valid['not_after'])
print(valid['not_before'])
print('================signatureCert=================================')
algosign, value = c1.signatureCert()
print(algosign)
print(value)
print('================KeyUsage=================================')
ku = c1.KeyUsage()
for key in ku:
    print (key)
#    print(ku)
print('================END=================================')
