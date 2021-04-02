1. laboratorijska vježba - Password manager

Implementacija password managera je u Pythonu koriste se standardni library sys i pycryptodome.
Password manager pokreće se sa komandom "python pwd_manger.py".


Postoje tri načina rada - init, put, get
python pwd_manager.py init [master_password]
Incijalizira novi vault (strukturu za pohranu lozinki) u folderu gdje se nalazi i python kod
u file-u "vault.bin". Ako se init pokrene još jednom dok postoje lozinke u fileu vault će 
se napraviti ponovo i sve lozinke i adrese će se obrisati. Za pohranu koristi se binarna
datotetka.

python pwd_manager.py put [master_password] [address] [password]
Stavlja novi par adrese i lozinke u vault. Ako već postoji lozinka sa određenom lozinkom
ona će se osvježiti novom lozinkom. Priliokm poziva dohvata lozinke korisnik će dobit
najnvoiju lozinku.

python pwd_manager.py get [master_password] [address]
Dohvaća lozinku za određenu adresu. Ako ne postoji adresa u vaultu korisnik će dobiti
odgovarajuću poruku. Ako je dodana nova verzija lozinke za određenu adresu korisnik će 
uvijek dobiti najnvoije osvježenu lozinku.


Tehničke specifikacije
- za funkciju derivacije kjuča iz master passworda koristi se PBKDF2 algoritam
- PBKDF2 provodi miljun iteracija računanja kjluča
- priliokm računanja HMAC-a unutar implementacije algoritma koristi se salt duljine
16 bytea i algoritam HMAC-SHA512
- ključ je veličin 32 bytea

- za kriptografiju parova adresa i ključeva koristi se AES256 algoritam u modu EAX
    -https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/eax/eax-spec.pdf
- EAX mod koristi nonce i tag pomoću kojeg možemo odrediti integritet vaulta
- ako dođe do korupcije vaulta možemo to detektirati

- svaka adresa i lozinka pojedinačno zauzima blok od 514 bytea u fileu
    - 256 - adresa bytea
    - 256 - lozinka bytea
    - 2 - separator između lozinke i passworda te separator za cjeli par
- na taj način napadač ne može znati ništa o veličini ključa i lozinke osim da je maksimalna
veličina kjuča i lozinke 256 bytea
