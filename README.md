# karmaProject

Final project in "Wirelles networks defance" course 

Authors - Anna Sandler, Jessica Flicker, Eden Reuveni

The evil twin is a family of wireless attacks (AKA Rough wireless attacks) whose
main goal is to create a twin, malicious access point and to make the users connect
to him instead of the distinct AP. Today’s WIFI networks are based on technology
named (Protocol) 802.11, these types of attacks are possible because this protocol
allows stations to roam freely between access points that share the same ESSID.
Even though stations must be authenticated to the ESS in order to associate with an
access point, the 802.11 protocol does not require the access point to be
authenticated to the station. there is no additional authentication needed to connect
or disconnect from a WIFI AP. spoofing ESSID is very easy and does not require any
checksum, validation, or key, and therefore - creating a fake AP is very easy.

## Classic evil twin vs. Karma attack -
In the classic evil twin, the attacker must be in the range of the network he replicates.
He first picks an AP to attack, replicates it, and then makes the user connect to him
by sending beacon packets with a much bigger frequency. in the karma attack, the
attacker doesn't have to be in the range of the network he replicates, he first picks a
user device, listens to its prob requests, picks a prob request, and replicates his
credentials. the distinct AP can be thousands of miles away and the user will be
"connected" to it

## Why karma?
When trying to attack wireless clients, the attacker is hoping for users to connect to
him, it's not guaranteed. when executing a karma attack, we first pick a user and
guarantee he is the one getting attacked, of course, we need to send auth packets
much harder for him to connect very fast to the fake AP before the user connect to
another AP, but even in that case, we can execute a quick deauthentication on him
and auth on our evil AP
