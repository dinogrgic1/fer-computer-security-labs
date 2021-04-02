#!/bin/bash

rm vault.bin
echo "=========================================================="
echo "Test #01: Try to put password in nonexisting vault"
python pwd_manager.py put test_password address test123
echo "=========================================================="
echo "Test #02: Try to get password from nonexisting vault"
python pwd_manager.py put test_password address test123
echo "=========================================================="
echo "Test #03: Init vault"
python pwd_manager.py init test_password
echo "=========================================================="
echo "Test #04: Get address doesn't exist"
python pwd_manager.py get test_password address
echo "=========================================================="
echo "Test #05: Set address and password"
python pwd_manager.py put test_password address test123
echo "=========================================================="
echo "Test #06: Set address and password wrong master password"
python pwd_manager.py put test_password1 address test123
echo "=========================================================="
echo "Test #07: Get address exist"
python pwd_manager.py get test_password address
echo "=========================================================="
echo "Test #08: Get address exist wrong master password"
python pwd_manager.py get test_password1 address
echo "=========================================================="
echo "Test #09: Set address too long"
python pwd_manager.py put test_password fnwg87fPQA6S2ZkHKllb7aPthiVB8kk57ebUxtw9dPZyW6EQPctarntVj3X6jscb8Nw5KflzAESrokj33RqtW1NPNE1XDSykrCCuq9fuQQtLw4YnepZKkgCLeFExaNC3FWICQ4ubA4pKHXuhqE9oDOCJuvKwX0ebJMX8nFmVdUr6BvrYV1Bjkb34grRfnUuJQlOrwaXMa0DPCswbYZyhsA2u1zmoGwpHJDmvn6BTHuP8Jf9F2Olcz0kUbnPSG2jri test123
echo "==================================================="
echo "Test #10: Set password too long"
python pwd_manager.py put test_password address fnwg87fPQA6S2ZkHKllb7aPthiVB8kk57ebUxtw9dPZyW6EQPctarntVj3X6jscb8Nw5KflzAESrokj33RqtW1NPNE1XDSykrCCuq9fuQQtLw4YnepZKkgCLeFExaNC3FWICQ4ubA4pKHXuhqE9oDOCJuvKwX0ebJMX8nFmVdUr6BvrYV1Bjkb34grRfnUuJQlOrwaXMa0DPCswbYZyhsA2u1zmoGwpHJDmvn6BTHuP8Jf9F2Olcz0kUbnPSG2jri
echo "=========================================================="
echo "Test #12: Corrupted vault"
echo "123" >> vault.bin
python pwd_manager.py get test_password address
echo "=========================================================="
echo "Test #13: Reinit vault"
python pwd_manager.py init test_password
echo "=========================================================="
echo "Test #14: Get adress from reinit vault -- should fail"
python pwd_manager.py get test_password adress
echo "=========================================================="
