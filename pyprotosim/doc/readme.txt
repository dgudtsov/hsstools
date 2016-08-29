Python Protocol Simulator
-----------------------------

Copyright (c) 2012-2014, Sergej Srepfler <sergej.srepfler@gmail.com>
EAP calculations use parts of hostapd code (http://w1.fi/hostapd)
Copyright (c) 2004-2008, Jouni Malinen and contributors. All rights reserved.
EAP-SIM calculations use a3a8 code (http://http://www.scard.org/gsm)
Copyright 1998, Marc Briceno, Ian Goldberg, and David Wagner. All rights reserved.

This program is licensed under the BSD license.

Intro
-----

If you are like me, you just hate that "itch". Something that is bothering 
you, and the best solution is to scratch it. Well - this is my scratch.

There is no portable diameter client. At least I don't know about it. I have
been toying with the idea to write one for a long time, but... the amount of 
work seemed high, and there never was enough "need" for me to do it - until 
now. Luckily for me, I stumbled upon the Python Diameter Library. 
Unfortunately, I could not use it on my project, so I just used some ideas and
here is the result.  Also I "borrowed" from hostapd server all the EAP 
calculations I needed (since I could not find python implementation - and even
when I did (milenage and hmac1) - it did not work on target platform without 
additional installations). 

The goal was to have:
- a PORTABLE diameter client (that means no installation required, just unpack 
  and run, without changing existing applications on system) 
- primary usage is TESTING, not heavy load or simplest usage
- must work on x86 Solaris 10, Linux and Windows
- dictionary is mandatory (to easily test mismatched AVP or modify values)
- unknown AVPs need to be easily manageable (inserted without defining in 
  dictionary)
- the client should be able to perform necessary EAP (AKA and AKA') 
  calculations
- must be able to send deliberately malformed packet

And it worked like a charm. So I got carried away and added support for 
radius. And DHCP. And LDAP. And SNMP is planned :-)
Now on more serious note:
 - DHCP client was done simply as a proof that python can easily send RAW 
   packets. But it is not tested enough, especially in multi-homed environment
   (more than one network card). 
 - Similar goes for LDAP library. I tried a new approach, but - yuck: I don't 
   like it. It will most definitely be rewritten (as soon as I figure out more
   about schema and other stuff. And have more time).
 
Naming
------

Original name was about testing AAA server I was testing on. But as the 
project grew, that name had to be changed. Finally, name was settled to 
PYthon Protocol Simulator (pronounced as "pipes"). 

Features
--------

- no installation required (well, almost. You'll need to install python 2.X on 
  windows platform.)
- tested with python 2.4-2.7
- use simplified dictionary (minimal features - user must know what is needed)
- easy encode unknown AVPs as HEX-string (just copy it from wireshark)
- client examples included
- supported protocols: RADIUS, DIAMETER, DHCP, LDAP, SMPP
- EAP: calculate SIM keys
- EAP: calculate AKA keys
- EAP: calculate AKA' keys
- EAP: calculate hmac1
- EAP: calculate hmac256
- EAP: decode AT_ENCR_DATA to get Pseudonym/Re-auth Identity
- EAP: HSS simulator
- RADIUS: encrypt/decrypt password
- LDAP: LDAP server simulator
- tested on Linux, Solaris 10-x86 and Windows XP

I did not bother too much to analyse/decode packets. Wireshark is much better 
tool for such details. It should be rather easy to add support if you need it .
Please note that it is not fully tested (I never needed some types, and I'm 
not developing it as universal library, so be warned...)

Sources
-------

Initial diameter code and some ideas are based on the code from 
http://i1.dk/PythonDiameter/
You will probably fail to see similarity, but... encoding part is essentially 
the same, although approach is totally different.
EAP-AKA and EAP-AKA' calculations use parts of the code from 
http://w1.fi/hostapd/
Dictionary is based on the data from the Wireshark dictionary 
http://www.wireshark.org
Parts of radius code are based on the code from 
http://pypi.python.org/pypi/pyrad
A3A8 calculation use code from http://www.scard.org/gsm
Parts od DHCP code are based on 
http://pydhcplib.sourcearchive.com/documentation/0.6.2-2/main.html

Detailed technical info (RFCs and other standards)
-----------------------

RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
RFC 2865 - RADIUS
RFC 2866 - RADIUS Accounting
RFC 2868 - RADIUS Attributes for Tunnel Protocol Support
RFC 3588 - Diameter Base Protocol
RFC 3748 - Extensible Authentication Protocol (EAP)
RFC 4186 - EAP-SIM
RFC 4187 - EAP-AKA
RFC 4740 - Diameter Session Initiation Protocol (SIP) Application
RFC 5448 - EAP-AKA'
3GPP TS 35.206 - Specification of Milenage Algorithm Set 
FIPS 186-2 + Change Notice - Pseudo Random Function
RFC 2132 - DHCP Options and BOOTP Vendor Extensions
For full list check at http://www.zytrax.com/books/dhcp/apc/
RFC 4510 - Lightweight Directory Access Protocol
For full list check at http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#RFCs
SMPP Developer’s Forum, SMPP Protocol Specification v3.4, 10/12/1999
and probably some others I forgot to mention while researching some issue

Developer's note
----------------

Feel free to modify the code/refactor it to be more concise. I did not 'plan' 
to write it as it is now. I had too little time to came up with this tool, so 
you can called it 'glued together', not designed. And it was written with the 
idea that almost anyone could take a look at the code and make modifications 
to suit his needs, so no fancy coding or too language-specific features were 
used. Mostly :-)
So - if you like OOP or want to have more consistent feel - rewrite it to suit
your needs. I definitely don't plan to. Adding a feature I need (or a 
bug fix) is a highly possible. But no other plans. Yet :-)
This was never intended to be "heavy traffic" tool, but simple (and versatile)
testing tool. 
I know that for DHCP you have Options, not AVPs, but... to stick with similar 
naming/code, I just renamed them. And you also have DHCP dictionary :-)
In LDAP I tried not to use dictionary, but I don't like how the code looks 
like. So it is possible that I'll switch to "dictionary approach". And I do 
not like how code decodes LDAP packet (not decoding itself, but determining 
relations between them (parent/child)). So it will probably change also. 

Simplified dictionary
---------------------

I "hate" unmaintainable dictionaries. So this one is as simple as I could make
it without too much fuss.
I know that in diameter you can specify AVPs per Application Id. I did not 
need that type of complexity. So I simplified.
You have basic types. You can define "typedefs" which are aliased to basic 
types. You have vendors and AVPs. Only minimum of fields definitions are 
present. Enumerated types are included for your reference, but not used by 
design, so the dictionary can survive without update (It means that value 
will not be decoded into name, but left as integer). Grouped AVPs are defined
as container only.
Including other dictionaries is not something I needed at design time.
So feel free to modify it to full blown dictionary. I did during experimenting,
and then choose to "simplify" it. But then - your mileage might wary. 
Using wireshark dictionary directly was an option, but... I needed multiple 
test dictionaries and this approach was abandoned.
Code to create simplified dictionary from wireshark dictionary files is 
included. (I have a gigantic adoration for Wireshark - can you tell? :-))

License
-------

This software may be distributed, used, and modified under the terms of
BSD license:

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name(s) of the above-listed copyright holder(s) nor the
   names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

