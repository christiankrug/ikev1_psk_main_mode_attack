# Attacking IKEv1 PSK Main Mode
The goal of this script is to run a wordlist attack against the IKEv1 PSK Main Mode protocol using an existing pcap capture. Given the scenario of an active attacker, the first five messages are sufficient to derive the `SKEYID_e ` key for each wordlist entry. This key is used to encrpt the fifth message in the protocol. If the correct key is used, the fifth message can be decrypted and will show the known responder ID. Thus, the attacker knows the correct key was used.

This is an active attack, because the attacker needs to provide their own Diffie-Hellman public value to calculate the shared Diffie-Hellman secret, later used to derive the keys.

The exact protocol usage can be found at https://tools.ietf.org/html/rfc2409.

The first five handshake messages that the pcap needs to include are:
1. Initiator Proposals
2. Responder Proposals
3. Initiator Diffie-Hellman public value `g^xi` and Initiator nonce payload `Ni`
4. Responder Diffie-Hellman public value `g^xr` and Responder nonce payload `Nr`
5. The concatenated string of Initiator ID and Initiator Mac encrypted with the key `SKEYID_e `.

In this specific example the encryption algorithm used is AES128-CBC and the hash algorithm used is SHA1 as found in the negotiated proposals.