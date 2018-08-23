#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#

import sys
import os
v = sys.version
if (v[0] == '2'):
    import tkFileDialog
    import tkMessageBox
else:
    from tkinter import filedialog, messagebox

import fsb795
#import pyasn1  # $ pip install pyasn1
import datetime
import subprocess
#Русификация даты
import locale
if sys.platform != "win32":
    locale.setlocale(locale.LC_TIME, 'ru_RU.utf8')

from datetime import datetime, timedelta

from pyasn1.type import univ, namedtype, tag, char, namedval, useful
#from pyasn1_modules import pem
from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.codec.cer import decoder
from pyasn1.codec.cer import encoder



try:
    from Tkinter import *
except ImportError:
    from tkinter import *

try:
    import ttk
    py3 = False
except ImportError:
    import tkinter.ttk as ttk
    py3 = True



#global time_end
#time_end = '2999-12-31 53:59:59'
global mfr
global image_cert_36x50_ok
global image_cert
global image_cert_36x50_bad
global image_cert_bad
global image_me
global start
global filename
global varUtil
global tick_cancel
global cmd_pp
global cmd_openssl
cmd_pp = "pp"
cmd_openssl = "/usr/local/lirssl_csp_64/bin/lirssl_static"
tick_cancel = 0

filename = ''
start = 0
me_32x50 = """
R0lGODlhIAAyAOf/AIhqX5RsWJ96ZEWLzYWAf06Kx0aPyj2R0puAbYuEfYWHhE+SwVGRxkCW0GeQqUuWy02V0JOJfYyLg5WKeIqMiW2RspOLhE2ayJ2Ke5GMi1eYyF2X
wU+azmOWu5yLgUad0Y2PjJuOd1abw5OQgqSNcnOWq5mPg5KSiVqcy6KPf1KfzZeRkJGTkGqbtFagwGmax5mSi1qfx6aRe5+TgaGUfZmWiJ2Vjp+ViVuls2OhxJiXj2ag
yl+mqZaYlaaWel+jzLGTepyXlq2We4OeqLCWdrWVdmGnvJObo6SZjaiZgqKak5qcmXWjwmmmynekt3Gkya6Zg6iZlaabiZidn6GbmqCdkH+jt2espa2aioahuLuZdbSb
en2lwHGoxrScgZ6gnYSkxLebh7ybfaefma+fgqqfk7qcgq6fiKyfjq+ek2qxp3OxkLqfecGec3qrxK2hocGfeoeqv7mhhpemuaOloruigaOnl6GmqLiijMqfd5WptM2e
fcChiJmrmNScgLWjmbSljcOka8iicsaieJapwaimqr+ij8Gkd5Crwqympa6moM6ghbillcClfsSlc6eppsakf7ynf8WkhcCmhcmlequqoZ+tp8Coeranop2ttL6pgMqo
armoncSogayqtMaqasGojbyqirGrqq6ssM6qZsuog7eqq5ixwr6qmrSrsc2pfs+peaGwvcutZcurecarisKqoc2sdMishbCuwKuwwMutgLiyi7WwqbWvusSumLexo9St
druvr9eriL6vqqS0x8mvjrmwttWufdOug92rhM2wicWyjrWzt76zoNGxfqi2xtCxhL6yssOzm9OwitGwk7qzv7G2xbi0xcWzqcOyusyzmLW2wL60ur+4nte1fNW1gtO1
iMu3jb22wtu0g9m2d8O3t9q1ise3stO3j8i2vrm6xMK4vuC3gMC6xc25qdq5hti5jNO7jNW6mNW8h967gti7lNm9guK6ic6+ptW/ld6+ity+kNjAkNrBjKvH3t/CgNzG
gtvGieHKgOLNfP///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAgADIAAAj+AO8IHDiQjkE6X75MWfJlicMeEFmwAAGCgkUFBQkKpFPIoEKICx9GZHHi
BIUMGAUWurPS4B2OdKZUpFiRhcgeJU9ksKjxzqNHHpewoFADhoQTRyUoWNFDhw6cJ0Ds5Mhy5aNEj4TqqCKFzAwfNCb4mGFC6QmnOk6smMqx0FWsPWrcQBMqCZkJE0L4
uMRGr1IJTtVmAEEnUaFCiRJVCmJBQoRQss4kiTBhRp1IlyKJnUCAgI2cGRA/OpyICgwLJiZB6uSFxmQynTQ1itSIxIQRBCisyGn18JQVSJAAelUKUh0hXpJ06lRrEBw4
REJESEBgBYwTFtw+EvUFeBk0gCT+waFEic2hSbJKDRLEftAWvAQswIBh4upPEFXAAwI1HtIgSoNAQkkegrRxSBsG+jBBBArYcIMJiClChQVVnGEMKJM0UtwgqwjiX3uD
tPHfezN4ZgMMoiQiSgYmoGGMLJN4Ucckk6jS4SCOOFJgGwVC0sgMNFR3oiijiGLBDJN0MokcXhQhYyOxRBlIG5B4IQQRWzTSyBY+JJCBDTYUmYgFUjwnByMCCADEFocE
sgkpgRwyoxAkQEFGI3VMtoISQYwyShQWnAGJKq8YEoCacDjySStwsjGPIQAggMcWbMAxmQ1KKOGJKIx4IEctydQihoj/ObJJK5s4UgcyYQQQxqT+RWghQwpJKBHFKLdM
koIYlAyjjTDZrLIKJa58QkqqxcAoRoZsaKHFBEJggcQNqZjyChRAwOFrMsMkE6qprXxySDHJltIIG2JoUQQGIUwbpinG8CEGHMuos0wxy9yrKJxikFtMcXCw0QYRYwVn
Q7XAiFdKMdsss83DyxRLiiOD3LtMMq44J6sQUgSHxCip5FJKKarUQu7DELsSiyCu5OvtsHBoIQQUaZRh6yim/PGMKqokk2+96qyjTTKUJLONN8AKs0uAYgiBRhpRjHEr
L6ZUM4wr3g6djTrbDF1Lvtl8k00sw1JSBxZPlyF1KsH4koszw+SrzTIwyjHJKzR2kkz+NtnsIiwlkvzByB9qj3FMMLzAsk23c3eCx+NyRG53LXwLI2wphgz+hyJvvBHM
576Mc/HckvBh+t0jy7J3NsIIMwwojHDyByaYKGJ4MMz4Ug2+2nhTyiJ+BL/HIqUM8845QydTTC6oxM4J7Z4fwwwz1YzjqzfDhNMLMb304gww6xwvzDLO5MIJKpw8Tzsm
uEBzDTPTWL8M9uqEU8/98KwjzznehOPMM77whS4CaApeUC0Y13gfM3LRNW9oIxz2s4cE6yEPefTvGdMABzim54vpGRAXn8Od7sKhjhKuox4TrOA6wtGOaYhDg+BIIDOu
8TkQ4oIXzDgGL6pxQgn68H7+64BHO9IRQ3MY0RwJfF8wUoELXLwPGlmwAjLuh8IJ2kOI2ACHOY5hjm4ckRoJhAYT3XcNQohgAXaohzvWsY38SdAdxnDCKY5hDXQckRzk
CGMToQENWuxgAxuwRTzi4Y41xqOEhHRCE1hhDXPYkRxGvIY5oNHE9oEBBRqoADsG6Y5BelIf7HCACJrwi27U8Yjd6AYlm0gLFVxgAUd4hzvYwY5OFhIf+IBHCRaggiYg
ghXlQGUqKwmGP3agGWpkBzcKOUsfDoEBGojBE35RDnSgoxvlsEY3KjkLQoAhC/wA5TiWWct73AMf+ujDAkQgTWqWIxrWsAYtrIGLWdSTEC/+YAI39rEPdqxjjfagRz/6
sQ9LLCAHcTiFMuAZT1NCwxOzmMMLOACBHdBBoO6Ahz3uwY999MMf2OjADpjwhB2M9BTRkIYpuyFRCLi0ATuwQjPYwU988MMf/eCHLnJwARV84KcfUIEKnhAHQqT0BQdI
KgQawIEn6AEZ8MCHP/zBD3rcwgox+MEPhArUoKpAmqcowAEMkNQHaAAFKLACNtpxTntYAhFdiIEKUMDVrn4ArUwYAFkN8ACzouADTm0GPeChC0Q04QKIjQFdjaAGFFyA
Ax/gAAogYAC9GuCyZr3AD/KRCWzoggs5iIEIvpqD0l5hDVfggQg40ACXFsAADLhZLF818IALdOEUlnBCDkSAWMSK4Lc8wIELXIACDnCgr6+VbQM0oIELaKAJbmhBb517
gRi4oLQuuEADmNpXihbgu7Lta213y07R8hYFMQgtb1WgAeM+gAGxDQgAOw==
"""

image_cert_36x50_ok = """
R0lGODlhJAAyAOf/AHAFCGgKCXwKEXcQD3USFIkOEo8PD4QTEIMTFn8YFH8YGocXGJcTGpIZGIocG5IaHn8gIZ0ZF4seIY8gHp0cHlQwNqUbHK8ZG5ggIpkhHaIiIpsk
JKIiJ5QnJ4crK7QfHq0iIZ4mJtoXDq4kKKgnJdsaGKgoK7gkJ48wMbIoJaQtLZ0vM60sKUpHVrUsLbAvKwBcgdomGLkvKsEtLNonIHRCRboxMQ5dfZ06OrsyNwBjg90t
KRRggMA1NLc4N1tRYhhigmVQWQloiKJCQrc9P9M2Mq9DQ8g9NTNjesc+QN45MptLSiBqhcRCNC1ohMZEPKdNTbtJRC1tiMhGQ95BO9BFQMxHOcZJSsZLPsZLRM1KQTtw
h79RT8dSQUhxieBLRNBQRM9SSkxzhuJNS8lVSc5TUVdyiMpXUL1bVsdaUGV1hspcWdhZUeRXULJlYs9gSs9gUNVfTNVfUtRfWNddY3N4h8djZclkXdBjV9ZiX9FkX+Vf
WX95hXp7hIh4hcxoadFqYeNlYNBqZ9lpXpF7gqB5g9lrZtduYNJxZc9xcK95gdZwbNhwZ9Jya59/hrR6fal9gcp1cORvZc52bJqDisp4eaWCg910a+dyb9x1ctl3atd3
cNZ3ddF5dcR8frx/fdN6cLSDgryBhMWAeNh9bbGGid18dNt8e9J/fuB9cdl/ddSBdNiAe+KBeeGBf96DeeiAfN2Df9+EdNyEhcOLituGetKIhNiHhduIgNiKe9KLi+KI
g9mMgrWVleuIgeKMgOOPiOiOieOQju+NituYluOXk+SYjN+ak9SdnO+Zk+Glo9Gtq/Globi6t+exr76/vO+ysMq9vuW2tN27usLEwdfAvdDDw83HxsfJxvW/v8vNyvDG
w9nMzM/RzufMytPV0d/S0tbY1eTX2Nnb2N3f3PfY1+rd3eDi3/Td2ePl4ufp5fXo6P7m4+rs6fDr6enu8O7w7fvt7u7y9fHz7//z8/T38/j2+vv29PP4+/f59vz6/v/6
+fr8+fn///3//P///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAkADIAAAj+AP8JHEiwoMGDCP8R2qXq1KJYsV7FOjQLF65Zg1i9UsXK0K1YqlQZ8rSR
1aKQr+oIhHXmSTE8tsi4zGIrjJZiWXiRwXIsC7A0WYyR4TWljLBFxrAgiiXwVRlE0qJKleZsqtSqVq9G7YTnlUBRxkD180e2rNmzaNE2AkZI4CIsnNCSU0c3nbpzdsmN
O/eN3Llx885umpJJIC5gicry0+s33F6+fxmTmzxO7zh+ZBvtsiRQ1pxGackuPjc3nWly6UL7a3SolcBYaUCrVmf6HO12dlU3OsNK4KdfnfxhNssvn7962/DVQ8evuPHQ
m3ZR8o0neD147drBU1dPHbx6mGD++Suh2uymOY9e4wJdz3Z3dcKbi4hRIkb5so1A8RJYK8wmf/k8hls46nhTXwwIBnPPPgwSV9YmYdQi0C2ZgNbOXOe4Jw2CHHYYwx7t
1JUOPJl5JNAjhlj3jVnxeNghDeSFBgogqAjEhylx1dONNtqk882BHpawhzfjhPOMNiuap0oorwECGjzYYKNNlC7GMMxePGoTWiN6uGKYf/7Ao80z2IxjDQ0utkGNlFE+
Q86U32BDjj+bpCHhP4eBps6RzawJZIe4SNlMO0iWmeRqu+gi0CRw+aMONd1QM+UXVX543yZPLPIVMHHNs2eczfxY6Q7hkPMNj2c1IowjArkS23H+54TjWHb+VIqgaosA
4tU/rcAB2jx+hUibErbGQINfqZnF2p248NIpPNDCI898xcZQjj/ZCMaLHwKBMkWO+dRTDz/loFntGPiIcE89z2UC14TATOLPPPnUm8891SL4BT407NAcWYnsQotArYQB
Wj7zJCxuMOZWqu54JewzD2aNyHFnLHoIAmDC88CTDz7ofCHCnyWUIMk78CiDICa2rXaHl//c0kpw+aiTnc3pkDOPPPJ4QwMz7rzTTj7eUDHDDEWEQQs8/HCiCrf/fLIJ
zTmno104IdpWDQ00iKBE15zccoINNshgAw50IlKIQLNscjCyk32TDmSDeMiJDyEAEED+AAAkYIMRiRiy3z+vhAHKcd+oE843i3dj2znbmFuCLlwQEAACmCOQAAAsuNAV
27EsEuY343wTZ+J9ISnNDiWccYIDly8g+wIOPCCADVDYIpAnegQHDznhYNNNlKcSOGWZRqQAwOwO1P4ABhg0MEIlAvXxS1yEynmfERQQ0LzzGGzAAQcNnIDAa2dYSM0z
z1DT5/prTtknFw0g0MD90HNAAgssUGDDCAT7jKOocR+y9A8BGaAABTSwvxe4wAUksEEDBMILYSSmHVHaETZM941zbLAb3RjHEkBwAAaOYAQPJJsLfPCBGgikE1mISwHN
AoIIgAAEKXAB2ch2BV0oQFP+/0AFMGQzQ7LY0AIpSIHZbDCDMgjCArsoRVPgsAle3OIjs7hFRWbBxVjMIhZanIUbkJiCEcigB0kowy1S4ABG7AoXZ5ADHHFxCDjgogq4
GIQdp4ALPOBhF0nABRzusAAi+IALurjCBRoAhTMw5R9bgEUtdKGIULwiJajoRStS8ghKwKIVdUAFH1qRAhYogAEHIMAGWICGWrTCCQmJJUGQYAMS7I8F0MMABWTJy4HY
UgMaYEEGMPCAB5igl710wQaWyQIcYOB7E0BmLFXAgVyS4B8hmN0GpJkQFpiAAjl4AAewqQDZbSAB3DRIB1YgkA7g8h8TOJ9AIJDOWOKgA/8FAMBBAgIAOw==
"""
image_cert_36x50_bad = """
R0lGODlhJAAyAOf/AEYqLEwvMFM1NtoXDlw5N1k7PNsaGFw+QD5IVGU/Pl9BQmJDRABcgXo/O9omGNonIGxFRGVHSA5dfr0yLABjgnBJSN4sKRRggGtMTdgxJ9AzLck1
L3FMT3pKShhignRNS64+Oh9ifQpoh2pSU4ZLS3FSU3hRT8k+NVJdaTVkeuA5M3xUUiFrhXtVWMVDNS1phYZUUH5WVXdYWcZEPM1CPyRtiIVXV4FZVzJsiMVIQt9CPMVK
PbNQSYVcWotbWYNdYM5LQjtwh8tOPIhfXaRYUn5jYsxQQsdSQctQTkhxieBLRMVTSYtiYM1RSYBmZYpjZk1zhuJNS4dmZ1dyiJVkY95SS8tYUbdfUtVXTpJpaGV1hoxs
bdBbTsxfW89gStJeVs5gUNVfTNldWNddY89hVplvbcdkVHN4h6xraNhhVNhiWppydeVfWH95hZZ0dXp7hNNlYIh4hc5oX9doXJB7gpt6e9lqZKB5g5p7g9ZuX9lsa+hq
ZNVva9dvZshzbtJxZa95gdJya9ByceVvZrV7fqp+gs52bMF5d7p7eZmEi7B/f9x0cMh5eqSDiqOEhN51bNd3cOlybtd4dtR6cNN6dtt5bNx7dM9+fdh9beF6e9l+dLiG
iMGFfMCFgr+GiLGLjM2Ef8iFhdeDdtmDcauOjeCAfuKAedyCeOGCc9KGfd2DfuiAfNiFftuEhNeGheCFe92JfN6Kg+iHh+OJhOmIf9WNit6MituOhOOPh+2RjdWYlcic
mbihn+SXhuqWkOWZjuSZlM+ppNunprm0s/KopMq0trm7uOiutcW5ue2vq+q0suS2tMq9vr/Bvta+vsTFwve4tMfJxsXKzc7Ix/W/v8rMydbJys3Oy/HGw+XLydDSz9TV
0t/S0tPY29fZ1t3Y1tvd2vDY1ffX1t7g3fPc2eHj4OTm4/nh3uvm5Obo5ejq5/Tn5/7n4+zu6/jr6/Lt7Orv8e/y7u/09/L08f/z8/T38/j2+vv29PT5/Pf59fz6/v/6
+fr8+fn///3//P///yH+EUNyZWF0ZWQgd2l0aCBHSU1QACH5BAEKAP8ALAAAAAAkADIAAAj+AP8JHEiwoMGDCP/RmXWqFB9Vqk6pytMqFqtWc1S90qTKjitVmjTZCXWK
I59Tp16dEZjJygxgZGoteZmjVhMgwHLcWrIjZ6wlTX4tuZUDiS0+v4T8USXwFZI/y6JKXaZsqtSqVq9GpUTmlMBQtyb180e2rNmzaNEGwkVHIJ8dktCOS0e3XLpx5tKB
8zZuG7hy4OKdhZRjkcBYuASV5TcOHLhx3v6W2wZ477jLjRuD40c20KxPAlGpCZSWLOPL6cqZK4e3tL9AeUwJVEWGtOt05lbjVpfXdSArTP91gkXJH2ez/PL5q4cNX71z
/JIrLw1pViKBiMgUrxevXbt46er+qWtXL9IqfwZcm4X0hdBsVqTr2RWfznj0AQ4MOFBfNtCkWwLB0gQk/uQjWTvmeJNONvo54GAu9+wjIXJlQdIELAK5kglp7czFWnjL
OCjiiA6woQ5dqwn2mh6uCESIHdttY5Y7JI74QHqlTSLHJQK1YUpc9VxTzTWTNUiiAWxks1cz18i4niaKzCYHafFEE801VtbogCzdjFPNkKUFAkcpArGCBYHxXNNMNd5Y
80CNVTwTTTVzNgPONc9sE804/kBCBob/sIILaekwacwzzxg5IitXGqNONXp64+Rrs4QikCFw+ZPOM3jSqYSWJfIHyQx8CORJYv7Mo44xerKq6Ij+GXS5jZBnBWJLIwKV
Utty5XgTWTvq+AOqg67xIYdX/5gCBpWXtYOiCsM68MBf5tSahyiH3RJXPNxyKw9+0Togjj/UDHZLHAJNkgOQ+dRTDz/ivBluFPgMcE890y0CV4a4GOJPPPkEnM894Tqo
BD4PWBAdWYLM4olApjRBWj7dupuLvKDai54B+8TDWSBcAKpKF3wU2C3A+JyjxACKGmDAIPDEk4yDkdj1mhxk/uOKKcXlk4536vA2TjzwwJPNA8SgA087+WRjgbxKcMuP
JKegKxwkPZszTjneeXOiXc488MAAKoxNIjQV/nGHQK1AMvFlrPVVzmTjqBEtjv68I4j+Hak01cQky22TjqSSamPXONi8ucsnayhCyhMbDLAPWejc0AMYr7CtSsnx+LXN
NpCms804TS5jTQ8rLHAABkO08A7lEQgwBAy1CHQIHMW1s9eQVs6q4DTWrBAAAAIIMPwC02gzTAQYYADBDYwI9AYscbVDJ59noVPMCgAc4L33CqDjDzoQcGDCChD0UMBs
VpCmzjPNNPPMofA/40gPAYCvgAILDNPMMOZbwQpu8IEhrABio9HUM0rzA+7tbwELSMDr0PGBAfbggitgAgQEcgtbKMZ60dAGnj5HGSlEoAAQjCAynjEMC/ZgCDAcgg1G
IBBKNCEu6jFhAiDgPPGhw4L+Q2CCEN3ACwKUSmeD4k8FPnCAD3zAhx+wXBCFWAdSVOAzAjkFGCCRCld8pBWuaMVFWtGKQ9wAAia4BBkreIMVBHENjuDFDRLQB2SxYglc
iIUVYpEHMMSCBrGYgx9psIIKmGEWgAQDGg4ghScQ0Q0dSAARgCOQIKwCFrUAxCZeoZJLfMIUKiFEAjJhijNcwkc3uEEBIFAAAXDgBmiAhWwSQkuCpIAJAmxjBTDAgQ/U
8pcDEaAJTHCDXUYgAi0AJjB78AEOvHIFGEhhBJRJyxXIoALYPGAJvlcCaiZkgOlbgAn+UYIC7K+c3jSICTogkA4U8x8YWJ9AEpDOavoyAAcCCQgAOw==
"""
def exit_view():
    sys.exit(0)	

def btn_press(event):
    x, y, widget = event.x, event.y, event.widget
    elem = widget.identify(x, y)
    index_tab = widget.index("@%d,%d" % (x, y))
    if (index_tab != 2) :
        mainfr.ut.forget()
    else:
        mainfr.ut.pack(side='left')

def tick(time_end):
    global tick_cancel
    dt = datetime.now()
    clock = mainfr.nb_t0.text.f3
    if (tick_cancel != 0):
        clock.after_cancel(tick_cancel)
    time_string = dt.strftime('%Y-%m-%d %H:%M:%S')
    fi = mainfr.nb_t0.text.labimg
#    print ('TIME_END=' + str(time_end))
#    print ('TIME_TEK=' + time_string)
    if (str(time_end) < time_string) :
        fi.config(image=image_cert_bad)
    else:
        if (time_end != '2999-12-31 53:59:59'):
    	    fi.config(image=image_cert)
    clock.config(text=time_string)
    tick_cancel = clock.after(200, (lambda e=time_end: tick(e)))


reqFL = {
    'CN' : 'ФИО'
}

reqUL = {
    'unstructuredName' : 'Неструктурированные данные',
    'Country' : 'Страна',
    'ST' : 'Регион',
    'CN' : 'Организация',
    'O' : 'Наименование организации',
    'E' : 'Электронная почта',
    'L' : 'Населенный пункт',
    'street' : 'Улица, номер дома',
    'OU' : 'Подразделение организации',
    'title' : 'Должность',
    'SN' : 'Фамилия',
    'GN' : 'Имя, Отчество',
    'OGRN' : 'ОГРН (13 символов)',
    'OGRNIP' : 'ОГРНИП (15 символов)',
    'SNILS' : 'СНИЛС (11 символов)',
    'INN' : 'ИНН (10 или 12 символов)'}


def on_tree_select (event):
    #    print (event)
    f = mainfr.nb_t1
    curItem = f.listbox.focus()
#    print (curItem)
#    print (str(f.listbox.item(curItem)))
    item_text = f.listbox.item(curItem, "text")
#    print(item_text)
#    for item in f.listbox.selection():
#	item_text = f.listbox.item(item, "text")
#	print(item_text)
    f.text.delete(1.0, END)
    item_value = f.listbox.item(curItem, "value")
    if (item_text == 'serial' or item_text == 'face' or item_text == 'subST'):
        #    if (curItem == 'I001'):
        f.text.insert(END, item_value[1])
    elif (item_text == 'issuer' or item_text == 'subject'):
        #    elif (curItem == 'I002' or curItem == 'I003'):

        item_is = item_value[1]
#	print (item_is)
        a = item_is.rstrip(';;')
        al = a.split(';;')
        b={}
        for v in al:
            als = v.find('=')
            key = v[0 : als]
            b[key] = v[als+1:]
            value = v[als+1:]
#	    print(als)
#	    print (value)
#	    print (key)
            if (key == 'CN'):
                #		print ('CN 0=' + item_text + ' vlad_sub='  + str(vlad_sub) + ' vlad_is=' + str(vlad_is))
                if ((item_text == 'issuer' and vlad_is == 1) or (item_text == 'subject' and vlad_sub == 1) ):
                    try:
                        f.text.insert(END, reqFL[key])
                    except:
                        f.text.insert(END, key)
                elif ((item_text == 'issuer' and vlad_is == 2) or (item_text == 'subject' and vlad_sub == 2) ):
                    try:
                        f.text.insert(END, reqUL[key])
                    except:
                        f.text.insert(END, key)
                else:
                    f.text.insert(END, key)
            else:
                try:
                    f.text.insert(END, reqUL[key])
                except:
                    f.text.insert(END, key)

            f.text.insert(END, ':\n\t')
            f.text.insert(END, value)
            f.text.insert(END, '\n')


#        item_is = item_value[1].replace(';;', '\n')
#        f.text.insert(END, item_is)
    elif (item_text == 'issuerST'):
        item_is = item_value[1]
        item_is = item_value[1].rstrip(';;')
        it_is = item_is.split(';;')
        l = len(it_is)
        if (l != 4 ):
            print('Bad issuer signTools')
            item_isb = item_value[1].replace(';;', '\n')
            f.text.insert(END, item_isb)
        else:
            f.text.insert(END, "Наименование СКЗИ УЦ:\n\t")
            f.text.insert(END, it_is[0])
            f.text.insert(END, '\n')
            f.text.insert(END, "Наименование УЦ:\n\t")
            f.text.insert(END, it_is[1])
            f.text.insert(END, '\n')
            f.text.insert(END, "Сертификат СКЗИ УЦ:\n\t")
            f.text.insert(END, it_is[2])
            f.text.insert(END, '\n')
            f.text.insert(END, "Сертификат УЦ:\n\t")
            f.text.insert(END, it_is[3])
            f.text.insert(END, '\n')
    elif (item_text == 'keyusage'):
        item_is = item_value[1]
        item_is = item_value[1].rstrip(';;')
        it_is = item_is.split(';;')
        for kut in it_is:
            f.text.insert(END, kut)
            f.text.insert(END, '\n')

    elif (item_text == 'pk_notgost'):
        item_is = item_value[1]
        f.text.insert(END, "Алгоритм ключа:\n\t")
        f.text.insert(END, item_is)
    elif (item_text == 'infosign'):
        item_is_v = item_value[1]
        f.text.insert(END, "Алгоритм подписи:\n\t")
        ia = item_is_v.find(';;')
        item_is = item_is_v[0:ia]
        if (item_is == '1.2.643.7.1.1.3.2'):
            f.text.insert(END, 'ГОСТ Р 34.11-2012 с ГОСТ Р 34.10-2012 256 бит')
        elif (item_is == '1.2.643.7.1.1.3.3'):
            f.text.insert(END, 'ГОСТ Р 34.11-2012 с ГОСТ Р 34.10-2012 512 бит')
        elif (item_is == '1.2.643.2.2.3'):
            f.text.insert(END, 'ГОСТ Р 34.11-94 с ГОСТ Р 34.10-2001')
        else:
            f.text.insert(END, item_is)
        item_is_v = item_is_v[ia+2:]
        f.text.insert(END, "\nЗначение подписи:\n")
        for i in range(0, len(item_is_v), 32):
            f.text.insert(END, "\t")
            f.text.insert(END, item_is_v[i: i + 32])
            f.text.insert(END, "\n")
    elif (item_text == 'pk_gost'):
        item_is_v = item_value[1]
        f.text.insert(END, "Алгоритм ключа:\n\t")
        ia = item_is_v.find(';;')
        item_is = item_is_v[0:ia]
#        print (item_is)
        if (item_is == '1.2.643.7.1.1.1.1'):
            f.text.insert(END, 'ГОСТ Р 34.10-2012 256 бит')
        elif (item_is == '1.2.643.7.1.1.1.2'):
            f.text.insert(END, 'ГОСТ Р 34.10-2012 512 бит')
        elif (item_is == '1.2.643.2.2.19'):
            f.text.insert(END, 'ГОСТ Р 34.10-2001 256 бит')
        else:
            f.text.insert(END, item_is)
        item_is_v = item_is_v[ia+2:]
#	print (item_is_v)
        f.text.insert(END, "\nТочка ЭК (curve):\n\t")
        ia = item_is_v.find(';;')
        item_is = item_is_v[0:ia]
        f.text.insert(END, item_is)
        item_is_v = item_is_v[ia+2:]
        f.text.insert(END, "\nПараметры хэш:\n\t")
        ia = item_is_v.find(';;')
        item_is = item_is_v[0:ia]
        f.text.insert(END, item_is)
        item_is_v = str(item_is_v[ia+2:])
        f.text.insert(END, "\nОткрытый ключ:\n")

        for i in range(0, len(item_is_v), 32):
            f.text.insert(END, "\t")
            f.text.insert(END, item_is_v[i: i + 32])
            f.text.insert(END, "\n")
    elif (item_text == 'kc'):
        KC1='1.2.643.100.113.1'
#0x2a, 0x85, 0x3, 0x64, 0x71, 0x1
        KC2='1.2.643.100.113.2'
        KC3='1.2.643.100.113.3'
        KB1='1.2.643.100.113.4'
        KB2='1.2.643.100.113.5'
        KA1='1.2.643.100.113.6'
#0x2a, 0x85, 0x3, 0x64, 0x71, 0x6
        l_issuer = []
        item_is = item_value[1].rstrip(';;')
        kc_l = ''
        for it_is in item_is.split(';;'):
            if (it_is == KC1):
                kc_l = 'KC1'
            elif (it_is == KC2):
                kc_l = 'KC2'
            if (it_is == KC3):
                kc_l = 'KC3'
            elif (it_is == KB1):
                kc_l = 'KB1'
            elif (it_is == KB2):
                kc_l = 'KB2'
            elif (it_is == KA1):
                kc_l = 'KA1'
            f.text.insert(END, kc_l + ' Class Sign Tool')
            f.text.insert(END, '\n')

#    print ('on_tree_select END')

def shooseUtil ():
    global cmd_openssl
    global cmd_pp
    global varUtil

    if(varUtil.get() == '0'):
        if (cmd_pp == ''):
            if sys.platform != "win32":
                home = os.environ["HOME"]
            else:
                home = os.environ["ALLUSERSPROFILE"]
        else :
            home = os.path.dirname(cmd_pp)
    elif(varUtil.get() == '1'):
        if (cmd_openssl == ''):
            if sys.platform != "win32":
                home = os.environ["HOME"]
            else:
                home = os.environ["ALLUSERSPROFILE"]
        else :
            home = os.path.dirname(cmd_openssl)
    else:
        return

    if sys.platform != "win32":
        if (v[0] == '2'):
            filename = tkFileDialog.askopenfilename(initialdir = home, parent=root,
                                                    filetypes=[('Утилита печати ', '*')])
        else:
            filename = filedialog.askopenfilename(initialdir = home, parent=root,
                                                  filetypes=[('Утилита печати ', '*')])
    else:
        if (v[0] == '2'):
            filename = tkFileDialog.askopenfilename(initialdir = home, parent=root,
                                                    filetypes=[('Утилита печати ', '*.exe')])
        else:
            filename = filedialog.askopenfilename(initialdir = home, parent=root,
                                                  filetypes=[('Утилита печати ', '*.exe')])

    if filename == (): # Если имя файла было задано пользователем
        return
    filename = filename.encode("UTF-8")
    if(varUtil.get() == '0'):
        cmd_pp = filename
    else:
        cmd_openssl = filename


def shooseCert ():
#    global time_end
    global filename
    global start
    global mfr
    global image_cert
    global image_cert_bad
    global info_pk
    global cmd_openssl
    global cmd_pp
    global vlad_sub
    global vlad_is
    pemder = ''
    inform = ''

    if not filename:
        if sys.platform != "win32":
            home = os.environ["HOME"]
        else:
            home = os.environ["ALLUSERSPROFILE"]
    else :
        home = os.path.dirname(filename)
    if (v[0] == '2'):
        filename1 = tkFileDialog.askopenfilename(initialdir = home, parent=root,
                                                 filetypes=[('Файл с сертификатом pem', '.pem'), ('Файл с сертификатом der', '.der'), ('Файл с сертификатом crt', '.crt'), ('Файл с сертификатом cer', '.cer'), ('Любой файл с сертификатом', '.*')])
    else:
        filename1 = filedialog.askopenfilename(initialdir = home, parent=root,
                                               filetypes=[('Файл с сертификатом pem', '.pem'), ('Файл с сертификатом der', '.der'), ('Файл с сертификатом crt', '.crt'), ('Файл с сертификатом cer', '.cer'), ('Любой файл с сертификатом', '.*')])

    if (filename1 == () or filename1 == ''): # Если имя файла было задано пользователем
        return
    filename = filename1
    cert_tek = fsb795.Certificate(filename1)

    if (cert_tek.pyver == ''):
        if (v[0] == '2'):
            tkMessageBox.showinfo(title="Выбор сертификата", message='Выбранный файл ' + '\n' + filename + '\nне содержит сертификата')
        else:
            messagebox.showinfo(title="Выбор сертификата", message='Выбранный файл ' + '\n' + filename + '\nне содержит сертификата')
        return
    if (cert_tek.formatCert == 'PEM'):
        pemder = " -a -i "
        inform = "-inform PEM "
    elif (cert_tek.formatCert == 'DER'):
        pemder = " -i "
        inform = "-inform DER "

    kc = cert_tek.classUser()
    if not kc:
        kc = ''
#    else :
#        print ('KC=' + kc)

    info_subject, vlad_sub = cert_tek.subjectCert()
#    print('VLAD_SUB=' + str(vlad_sub))
#    for atr in info_subject.keys() :
#	print ('SUBJECT=' + atr + '=' + info_subject[atr])
    info_issuer, vlad_is = cert_tek.issuerCert()
#    print('VLAD_IS=' + str(vlad_is))
#    for atr in info_issuer.keys() :
#	print ('ISSUER=' + atr + '=' + info_issuer[atr])

    serial_num = cert_tek.serialNumber()
    validity_cert = cert_tek.validityCert()

    info_pk = cert_tek.publicKey()
#    subsigntool = ''
    subsigntool = cert_tek.subjectSignTool()
    isusigntool = cert_tek.issuerSignTool()
#    xa = extract_ext_cert(cert["extensions"], "2.5.29.14")
    algosign, valuesign = cert_tek.signatureCert()
    ku = cert_tek.KeyUsage()

    time_end = validity_cert['not_after']
    time_start = validity_cert['not_before']
    dt = datetime.now()
    dtek = dt.strftime('%Y-%m-%d %H:%M:%S')

#    print (validity_cert)
#    for atr in validity_cert.keys() :
#        print (atr + '=' + str(validity_cert[atr]))

    f = mainfr.nb_t2
    f.text.configure(state='normal')
    f.text.delete(1.0, END)

    if sys.platform != "win32":
        home = os.environ["HOME"]
    else:
        home = os.environ["ALLUSERSPROFILE"]

    if(varUtil.get() != '2'):
        if sys.platform == "win32":
            if(varUtil.get() == '0'):
                cmd = cmd_pp + " -t c -u " + pemder + "\"" + filename + "\"";
            else:
                cmd = cmd_openssl + " x509 -engine gost -text -noout -nameopt utf8 " + inform + " -in " + "\"" + filename + "\"";
        else:
            if(varUtil.get() == '1'):
                cmd = cmd_openssl + " x509 -engine gost -text -noout -nameopt utf8 " + inform + " -in " + "\"" + filename + "\"";
            else:
                cmd = cmd_pp + " -t c -u " + pemder + "\"" + filename + "\"";

#    print ('CMD=' + cmd)
        PIPE = subprocess.PIPE 
        p = subprocess.Popen(cmd, shell = True, 
                             stdin = PIPE, stdout = PIPE, stderr = PIPE)         
        s = ' '           
        cert = ''
        while s:
            s=p.stdout.readline()
            if not s:
                break
            inds = str(s).find(': ')
            if (inds != -1):
                #    	    print('INDS=' + str(inds))
                its = f.text.index('insert')
                f.text.insert (END,  s[0:inds + 1])
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)

                if (v[0] == '3'):
                    ii = s[inds + 1:].decode("UTF-8")
                    f.text.insert (END, ii)
                else:
                    f.text.insert (END,  str(s[inds + 1:]))
            else:
                inds = str(s).find(':\n')
                if (inds == -1):
                    if (v[0] == '3'):
                        ii = s.decode("UTF-8")
                        f.text.insert (END,  ii)
                    else:
                        f.text.insert (END, s)
                    continue
                inds1 = str(s).find(':')
                if (inds1 != inds):
                    f.text.insert (END, s)
                    continue
                its = f.text.index('insert')
                f.text.insert (END,  s[0:inds + 1])
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                if (v[0] == '3'):
                    ii = s[inds + 1:].decode("UTF-8")
                    f.text.insert (END,  ii)
                else:
                    f.text.insert (END,  str(s[inds + 1:]))
    else:
        cert_parse = cert_tek.prettyPrint()
#        print(cert_parse)
        lcert = cert_parse.split('\n')
        i = 0
        while ( i < len(lcert)):
            inds = lcert[i].find(':')
            if (inds == -1):
                if (len(lcert[i]) > 0):
                    f.text.insert (END, lcert[i])
                    f.text.insert (END, '\n')
                i = i + 1
                continue
            its = f.text.index('insert')
            f.text.insert (END, lcert[i])
            ite = f.text.index('insert')
            f.text.tag_add('bold', its, ite)
            f.text.insert (END, '\n')
            if (lcert[i].find('issuer=Name:') != -1):
                for atr in info_issuer.keys() :
                    i_atr = info_issuer[atr]
                    l_issuer = '\t' + atr + '=' + str(i_atr)
                    f.text.insert (END, l_issuer)
                    f.text.insert (END, '\n')
                i = i + 1
                while (len(lcert[i]) > 0):
                    i = i + 1
#		print(len(lcert[i]))
            elif (lcert[i].find('subject=Name:') != -1):
                for atr in info_subject.keys() :
                    s_atr = info_subject[atr]
                    l_subject = '\t' + atr + '=' + str(s_atr)
                    f.text.insert (END, l_subject)
                    f.text.insert (END, '\n')
                i = i + 1
                while (len(lcert[i]) > 0):
                    i = i + 1
#		print(len(lcert[i]))
            elif (lcert[i].find('subjectPublicKeyInfo=SubjectPublicKeyInfo:') != -1):
                algo = str(info_pk['algo'])
                if (algo.find("1.2.643") == -1):
                    i = i + 1
                    continue
                its = f.text.index('insert')
                f.text.insert(END, "   Алгоритм ключа:")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                f.text.insert(END, "\n\t")
                item_is = str(info_pk['algo'])
                if (item_is == '1.2.643.7.1.1.1.1'):
                    f.text.insert(END, 'ГОСТ Р 34.10-2012 256 бит')
                elif (item_is == '1.2.643.7.1.1.1.2'):
                    f.text.insert(END, 'ГОСТ Р 34.10-2012 512 бит')
                elif (item_is == '1.2.643.2.2.19'):
                    f.text.insert(END, 'ГОСТ Р 34.10-2001 256 бит')
                else:
                    f.text.insert(END, item_is)
                its = f.text.index('insert')
                f.text.insert(END, "\n   Точка ЭК (curve):")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                f.text.insert(END, "\n\t")
                f.text.insert(END, str(info_pk['curve']))
                its = f.text.index('insert')
                f.text.insert(END, "\n   Параметры хэш:")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                f.text.insert(END, "\n\t")
                f.text.insert(END, str(info_pk['hash']))
                its = f.text.index('insert')
                f.text.insert(END, "\n   Открытый ключ:\n")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                item_is_v = str(info_pk['valuepk'])
                for i_k in range(0, len(item_is_v), 32):
                    f.text.insert(END, "\t")
                    f.text.insert(END, item_is_v[i_k: i_k + 32])
                    f.text.insert(END, "\n")
                i = i + 1
                while (lcert[i].find('subjectPublicKey=') == -1):
                    #    		    print(lcert[i])
                    i = i + 1
                i = i + 1
            elif (lcert[i].find('signatureAlgorithm=AlgorithmIdentifier:') != -1):
                its = f.text.index('insert')
                f.text.insert(END, "   Алгоритм подписи сертификата:")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                f.text.insert(END, "\n\t")
                item_is = str(algosign)
                if (item_is == '1.2.643.7.1.1.3.2'):
                    f.text.insert(END, 'ГОСТ Р 34.11-2012 с ГОСТ Р 34.10-2012 256 бит')
                elif (item_is == '1.2.643.7.1.1.3.3'):
                    f.text.insert(END, 'ГОСТ Р 34.11-2012 с ГОСТ Р 34.10-2012 512 бит')
                elif (item_is == '1.2.643.2.2.3'):
                    f.text.insert(END, 'ГОСТ Р 34.11-94 с ГОСТ Р 34.10-2001')
                else:
                    f.text.insert(END, item_is)
                f.text.insert(END, "\n   Значение подписи:\n")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                item_is_v = str(valuesign)
                for i_k in range(0, len(item_is_v), 32):
                    f.text.insert(END, "\t")
                    f.text.insert(END, item_is_v[i_k: i_k + 32])
                    f.text.insert(END, "\n")
                i = i + 1
                break            
            elif (lcert[i].find('validity=Validity:') != -1):
                ############################
                its = f.text.index('insert')
                f.text.insert (END, "    Начало действия сертификата:" )
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                f.text.insert (END, "\n\t")
                t_s = datetime.strptime(str(time_start),'%Y-%m-%d %H:%M:%S')
                t_s_1 = t_s.strftime('%A %d %B %Y %I:%M%p')
                f.text.insert (END, t_s_1)
                f.text.insert (END, "\n")
                its = f.text.index('insert')
                f.text.insert (END, "    Срок окончания действия сертификата:")
                ite = f.text.index('insert')
                f.text.tag_add('bold', its, ite)
                f.text.insert (END, "\n\t")
                t_e = datetime.strptime(str(time_end),'%Y-%m-%d %H:%M:%S')
                t_e_1 = t_e.strftime('%A %d %B %Y %I:%M%p')
                f.text.insert (END, t_e_1)
                f.text.insert (END, "\n")
                i = i + 6
##########################
            elif (lcert[i+1].find('extnID=2.5.29.15') != -1):
                i = i + 1
                f.text.insert (END, lcert[i])
                f.text.insert (END, '\n')
                for kut in ku:
                    f.text.insert (END, "\t")
                    f.text.insert (END, kut)
                    f.text.insert (END, "\n")
                i = i+ 3
            elif (lcert[i+1].find('extnID=1.2.643.100.112') != -1):
                i = i + 1
                f.text.insert (END, lcert[i])
                f.text.insert (END, '\n')
                for i_t in range(0,len(isusigntool)):
                    f.text.insert (END, '\t')
                    f.text.insert (END, str(isusigntool[i_t]))
                    f.text.insert (END, '\n')
                i = i + 2
            elif (lcert[i+1].find('extnID=1.2.643.100.111') != -1):
                i = i + 1
                f.text.insert (END, lcert[i])
                f.text.insert (END, '\n\t')
                f.text.insert (END, str(subsigntool))
                f.text.insert (END, '\n')
                i = i + 2
            else:
                i = i + 1
                continue


    f.text.configure(state='disabled')


    f = mainfr.nb_t0
    f.text.configure(state='normal')
    f.text.delete(1.0, END)
    dt = datetime.now()
    dtek = dt.strftime('%Y-%m-%d %H:%M:%S')
############################
    f.text.labimg = Label(f.text, text='', bd=0, relief='flat', bg="#f5deb3")
#        f.text.image_create(END, image=image_me)
    f.text.window_create(INSERT, window=f.text.labimg)

#######################
    if (str(time_end) < dtek) :
        f.text.labimg.config(image = image_cert_bad)
#        f.text.image_create(END, image=image_cert_bad)
    else:
        f.text.labimg.config(image = image_cert)
#        f.text.image_create(END, image=image_cert)
    f.text.insert (END, "  Информация о сертификате" )
    f.text.tag_add('bold', 1.0, '1.end')
    f.text.insert (END, '\n')
    f.text.f1 = Frame(f.text)
    f.text.f1.configure(width=550,height=2, background='snow')
    f.text.f2 = Frame(f.text)
    f.text.f2.configure(width=550,height=2, background='snow')
    f.text.window_create(INSERT, window=f.text.f1)
    f.text.insert (END, '\n')
    f.text.insert (END, "  Владелец:")
    f.text.insert (END, "\n")
    f.text.insert (END, "\t")
    its = f.text.index('insert')
    f.text.insert (END, info_subject['CN'])
    ite = f.text.index('insert')
    f.text.tag_add('bold', its, ite)

    f.text.insert (END, "\n")
    f.text.insert (END,  "  Издатель: ")
    f.text.insert (END, "\n")
    f.text.insert (END, "\t")
    its = f.text.index('insert')
    f.text.insert (END,  info_issuer['CN'])
    ite = f.text.index('insert')
    f.text.tag_add('bold', its, ite)
    f.text.insert (END, "\n")

    if (str(time_end) < dtek) :
        f.text.insert (END, "  Срок действия сертификата истек" )
    else:
        f.text.insert (END, "  Срок действия сертификата не истек" )
    f.text.insert (END, '\n\n')

    f.text.window_create(INSERT, window=f.text.f2)
    f.text.insert (END, '\n')
############################
    f.text.insert (END, "  Начало действия сертификата:" )
    f.text.insert (END, "\n\t")
    t_s = datetime.strptime(str(time_start),'%Y-%m-%d %H:%M:%S')
    t_s_1 = t_s.strftime('%A %d %B %Y %I:%M%p')
    its = f.text.index('insert')
    f.text.insert (END, t_s_1)
    ite = f.text.index('insert')
    f.text.tag_add('bold', its, ite)
    f.text.insert (END, "\n")
    f.text.insert (END, "  Срок окончания действия сертификата:")
    f.text.insert (END, "\n\t")
#####################
    t_e = datetime.strptime(str(time_end),'%Y-%m-%d %H:%M:%S')
    t_e_1 = t_e.strftime('%A %d %B %Y %I:%M%p')
    its = f.text.index('insert')
    f.text.insert (END, t_e_1)
    ite = f.text.index('insert')
    f.text.tag_add('bold', its, ite)
    f.text.insert (END, "\n")
###########ЧАСЫ############
    f.text.insert (END, "  Текущая дата и время:")
    f.text.insert (END, "\n\t\t")

    f.text.f3 = Label(f.text, font = ("times", 11, "bold"), fg='blue', bg="#f5deb3", relief='flat', bd=0)
#    f.text.f2.configure(width=550,height=2, background='snow')
    f.text.window_create(INSERT, window=f.text.f3)
    tick(time_end)


########################

    f.text.configure(state='disabled')

#########TREEVIEW##################################
    f = mainfr.nb_t1
    for l in f.listbox.get_children():
        f.listbox.delete(l)

    f.listbox.insert("", 'end', text='serial', values=('Серийный номер', serial_num))
    f.text.delete(1.0, END)

#    l_issuer = []
    l_issuer = ""
    for atr in info_issuer.keys() :
        i_atr = info_issuer[atr]
        l_issuer = l_issuer + atr + '=' + str(i_atr) + ';;'
#	l_issuer.append(atr + '=' + str(i_atr))

    f.listbox.insert("", 'end', text='issuer', values=('Издатель', l_issuer))
#    f.listbox.insert("", 'end', text=info_issuer, values=('Издатель', l_issuer))
#    l_subject = []
    l_subject = ""
    for atr in info_subject.keys() :
        s_atr = info_subject[atr]
        l_subject = l_subject + atr + '=' + str(s_atr) + ';;'
#	l_subject.append(atr + '=' + str(s_atr))
    f.listbox.insert("", 'end', text='subject',values=('Владелец', l_subject))
#    f.listbox.insert("", 'end', text=info_subject,values=('Владелец', l_subject))

    algo = str(info_pk['algo'])
    if (algo.find("1.2.643") != -1):
        spk = algo + ';;' + str(info_pk['curve']) + ';;' + str(info_pk['hash']) + ';;' + str(info_pk['valuepk'])
        f.listbox.insert("", 'end', text='pk_gost',values=('Публичный ключ', spk))
    else :
        f.listbox.insert("", 'end', text='pk_notgost',values=('Публичный ключ', algo))

    if (len(ku) > 0):
        keyusage = ''
        for key in ku:
            keyusage = keyusage + key  + ';;'
        f.listbox.insert("", 'end', text='keyusage',values=('X509v3 KeyUsage', keyusage))

    if (subsigntool):
        f.listbox.insert("", 'end', text='subST',values=('subjectSignTool', str(subsigntool)))
    if (isusigntool):
        ii = ''
        for i in range(0,len(isusigntool)):
            ii = ii + str(isusigntool[i]) + ';;'
        f.listbox.insert("", 'end', text='issuerST',values=('issuerSignTool', ii))

    if (kc != ''):
        f.listbox.insert("", 'end', text='kc',values=('Классы защищенности', kc))

    info_sign = str(algosign) + ';;' + str(valuesign)
    f.listbox.insert("", 'end', text='infosign',values=('Подпись сертификата', info_sign))


root = Tk()
try:
      # call a dummy dialog with an impossible option to initialize the file
      # dialog without really getting a dialog window; this will throw a
      # TclError, so we need a try...except :
    try:
        root.tk.call('tk_getOpenFile', '-foobarbaz')
    except TclError:
        pass
      # now set the magic variables accordingly
    if sys.platform != "win32":
        root.tk.call('set', '::tk::dialog::file::showHiddenBtn', '1')
        root.tk.call('set', '::tk::dialog::file::showHiddenVar', '0')
except:
    pass

root.bind_class("TNotebook", "<ButtonPress-1>", btn_press, True)

varUtil = StringVar()
varUtil.set(2)
#view_cert = Toplevel(root)
view_cert = root
#############
img_cert = PhotoImage(data=image_cert_36x50_ok)
view_cert.tk.call('wm', 'iconphoto', view_cert._w, img_cert)
view_cert.configure(relief='groove', padx=3,pady=3, borderwidth=3, background='#f5deb3')
view_cert.title('Просмотр сертификата')
view_cert.geometry("550x400+100+100")
#Стиль для TButton
ttk.Style().configure("TButton",borderwidth=2,anchor='nw',font="serif 8", background='#ff9060')
ttk.Style().map('TButton',
                foreground=[('disabled', 'yellow'),
                            ('pressed', 'red'),
                            ('active', 'blue')],
                background=[('disabled', 'magenta'),
                            ('pressed', '!focus', 'cyan'),
                            ('active', 'green')],
                highlightcolor=[('focus', 'green'),
                                ('!focus', 'red')],
                relief=[('pressed', 'groove'),
                        ('!pressed', 'raised')])

mainfr = Frame(view_cert)
mainfr.configure(relief='groove',background='#39b5da', bd=4)
mainfr.pack(expand=1, fill='both', pady=2)

mainfr.nb = ttk.Notebook(mainfr)
mainfr.nb.configure(width=400,height=300,pad=0)
mainfr.nb_t0 = Frame(mainfr.nb)
mainfr.nb.add(mainfr.nb_t0, padding=3)
mainfr.nb.tab(0, text="О сертификате", compound="left",underline="-1")
mainfr.nb_t1 = Frame(mainfr.nb)
mainfr.nb.add(mainfr.nb_t1, padding=3)
mainfr.nb.tab(1, text="Детали",compound="left",underline="-1")
mainfr.nb_t2 = Frame(mainfr.nb)
mainfr.nb.add(mainfr.nb_t2, padding=3)
mainfr.nb.tab(2, text="Текст",compound="none",underline="-1")
mainfr.nb.pack(expand=1,fill='both',padx=3,pady=3)
mainfr.sep = Frame(mainfr)
mainfr.sep.configure(height=6,bd=2,relief='groove',background='wheat')
mainfr.sep.pack(fill='x', expand=1, pady=2)
mainfr.buttclose = ttk.Button(mainfr, text='Закрыть', command=exit_view)
mainfr.buttclose.configure(style='My.TButton')
mainfr.buttclose.pack(side='right',padx=3,pady=6)
mainfr.buttshoose = ttk.Button(mainfr)
mainfr.buttshoose.configure(text='Выбрать', style='My.TButton')
mainfr.buttshoose.configure(command=shooseCert)
mainfr.buttshoose.pack(side='right',padx=3,pady=6)
#############Утилита просмотра#########################
mainfr.ut = Frame(mainfr, bg='#39b5da')
mainfr.ut.TRadiobutton1 = ttk.Radiobutton(mainfr.ut, variable=varUtil,value=0, text="NSS")
mainfr.ut.TRadiobutton2 = ttk.Radiobutton(mainfr.ut, variable=varUtil,value=1, text="OpenSSL")
mainfr.ut.TRadiobutton3 = ttk.Radiobutton(mainfr.ut, variable=varUtil,value=2, text="Python")

mainfr.ut.bututil = ttk.Button(mainfr.ut, text='Утилита', style='My.TButton',command=shooseUtil)
#mainfr.ut.pack(side='left')

mainfr.ut.bututil.pack(side='left',padx=3,pady=6)
mainfr.ut.TRadiobutton3.pack(side='left', padx=3)
mainfr.ut.TRadiobutton2.pack(side='left', padx=3)
mainfr.ut.TRadiobutton1.pack(side='left')
#mainfr.buttshoose.pack(side='right',padx=3,pady=6)

mfr = mainfr
f=mainfr.nb_t0
f.text = Text(f)
f.text.configure(wrap='none', font="Times 10 bold italic", background='wheat')
f.text.grid(row=0,column=0,sticky='nsew',padx=0,pady=0)

f.text.grid_columnconfigure(0, weight=1)
f.text.grid_rowconfigure(0, weight=1)

fnt_std = f.text.cget('font')
fnt_l = fnt_std.split(' ')
fnt_bold = fnt_l[0] + ' ' + fnt_l[1] + ' ' + 'bold'
fnt_italic = fnt_l[0] + ' ' + fnt_l[1] + ' ' + 'italic'
f.text.tag_configure('bold', font=fnt_bold)
f.text.tag_configure('italic', font=fnt_italic)
######################
f.text.f1 = Frame(f.text)
f.text.f1.configure(width=550,height=2, background='snow')
f.text.f2 = Frame(f.text)
f.text.f2.configure(width=550,height=2, background='snow')

def page1 (f):
    #f=mainfr.nb_t0
    global start
    global image_cert_36x50_ok
    global image_cert
    global image_cert_36x50_bad
    global image_cert_bad
    global image_me
    global me_32x50
    time_end = '2999-12-31 53:59:59'

    f.text.configure(state='normal')
    f.text.delete(1.0, END)
    image_cert = PhotoImage(data=image_cert_36x50_ok)
    image_cert_bad = PhotoImage(data=image_cert_36x50_bad)
    image_me = PhotoImage(data=me_32x50)

    f.text.labimg = Label(f.text, text='', bd=0, relief='flat', bg="#f5deb3")
#        f.text.image_create(END, image=image_me)
    f.text.window_create(INSERT, window=f.text.labimg)
    if (start == 0):
        validtext = '\n\tВыберите сертификат для просмотра.'
#        f.text.image_create(END, image=image_me)
        f.text.labimg.config(image=image_me)
        f.text.insert (END, "  Здесь будет информация из выбранного сертификата")
        f.text.tag_add('bold', 1.0, '1.end')
    f.text.insert (END, '\n')
    f.text.window_create(INSERT, window=f.text.f1)
    f.text.insert(END, "\n")
    f.text.insert(END,validtext)
    f.text.insert(END,'\n\t\t(Кнопка "Выбрать")')
    f.text.insert(END,"\n\n")
    f.text.window_create(INSERT, window=f.text.f2)
    f.text.insert(END, "\n")
    f.text.insert (END, "  Текущая дата и время:")
    f.text.insert (END, "\n\t\t")
    f.text.f3 = Label(f.text, font = ("times", 11, "bold"), fg='blue', bg="#f5deb3", relief='flat', bd=0)
    f.text.window_create(INSERT, window=f.text.f3)
    tick(time_end)

    f.text.configure(state='disabled')

#Детали сертификата
f=mainfr.nb_t1

f.listbox = ttk.Treeview(f, selectmode="extended", columns=("1","2"))
f.text =Text(f,wrap='none',font='Times 10 bold', background='wheat', height=10)
f.text.pack(side='bottom', fill='x', expand=1)
#f.text.configure(wrap='none', font="Times 10 bold italic", background='wheat')

#f.listbox["columns"] = ("1", "2")
f.listbox['show'] = 'headings'
f.listbox.column("1", width=120, anchor='nw', stretch=NO)
f.listbox.column("2", anchor='nw')
f.listbox.heading("1", text="Аттрибут")
f.listbox.heading("2", text="Значение")
f.listbox.pack(side='left', fill='x', expand=1)
# frame so they look like a single widget
f.vsb=ttk.Scrollbar(f, orient='vertical', command=f.listbox.yview)
f.vsb.pack(side='right', fill='y')
f.listbox.configure(yscrollcommand=f.vsb.set)
f.listbox.bind("<<TreeviewSelect>>", on_tree_select)


#f.text.configure(state='disabled')
#Текст сертификата
f=mainfr.nb_t2

f.text =Text(f,wrap='none',font='courier 8', background='snow', width=71)
#f.text.configure(wrap='none', font="Times 10 bold italic", background='wheat')
f.text.configure(wrap='none', font="Times 10", background='snow')
fnt_std = f.text.cget('font')
fnt_l = fnt_std.split(' ')
fnt_bold = fnt_l[0] + ' ' + fnt_l[1] + ' ' + 'bold'
fnt_italic = fnt_l[0] + ' ' + fnt_l[1] + ' ' + 'italic'
f.text.tag_configure('bold', font=fnt_bold)
#f.text.tag_configure('italic', font=fnt_italic)


f.hsb = ttk.Scrollbar(f, orient="horizontal", command=f.text.xview)
f.hsb.pack(side='bottom', fill='x', anchor='n')
f.text.pack(side='left', fill='both', expand=1, anchor='center')

f.vsb = ttk.Scrollbar(f, orient="vertical", command=f.text.yview)
f.vsb.pack(side='right', fill='y', expand=1, anchor='nw')

f.text.configure(yscrollcommand=f.vsb.set)
f.text.configure(xscrollcommand=f.hsb.set)

f.text.configure(state='disabled')


#Первая вкладка
page1 (mainfr.nb_t0)
#print (mainfr.nb_t0)

root.mainloop()

