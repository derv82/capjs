/**
 * http://security.stackexchange.com/questions/66008/how-exactly-does-4-way-handshake-cracking-work
 * https://github.com/roobixx/cowpatty/blob/master/cowpatty.c
 *
 * Specificaly https://github.com/roobixx/cowpatty/blob/master/cowpatty.c#L274
 *
 * http://sid.rstack.org/pres/0810_BACon_WPA2_en.pdf
 */

/**
 * Algorithm:
 *
 * Construct PMK using
 *  - passphrase (from user input or list) and
 *  - SSID (from user input or beacon frame).
 * pmk = pbkdf2_sha1(passphrase, ssid, 4096, 256)
 *
 * Construct PTK using
 *  - PMK (step 1)
 *  - AP bssid, STATION bssid, ANonce, SNonce (from Handshake 3 of 4)
 * ... (wpa_pmk_to_ptk)
 *
 * Construct MIC we expect to see in 4-of-4 using
 *  - PTK (Step 2)
 *  - EAPOL Frame (Handshake 4 of 4)
 */
