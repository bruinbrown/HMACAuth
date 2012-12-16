HMAC Authorization for ASP.NET Web API projects
===============================================

What is it?
-----------

HMAC authorization is a process of ensuring that the server receives what the client sends. This is achieved by using a key which the server and client know and a separate key which is shared with everyone.

What is it not?
---------------

It's not a form of encryption. I.e. Don't send passwords through it.

How does it work?
-----------------

The client takes all data which will be sent in the query string and the date at which the hash is taken. It then hashes it all using the private key. This hash is then sent to the server along with the date used and the public key.
The server then receives all of this data and attempts to replicate the hash with the given parameters.

Why is this useful?
-------------------

This allows you to add different levels of authentication to methods in your Web API project and ensure that anything sent is not subject to man in the middle attacks.

How do I use it?
----------------

1. Create your request as usual
   e.g. www.example.com/api?hello=world&test=true
2. Form a string  with all the values in the querystring and the date now in universal time
   e.g. worldtrue12/11/12 14:09:56
3. Hash this with you given password
4. Add the values to the headers below
   Key -> User's public key
   Hash -> The client side calculated hash
   DateSent -> The date you used when you hashed
5. Send the request

How do I implement it in my Web API?
------------------------------------

1. Add the required using statements
2. To all protected methods add the HMACAuth attribute along with an IEnumerable of APIUsers. This can be either an in memory List or it can be an Entity Framework DbSet
3. Consider named parameters for other setup. The options are as follows
    * SecurityProvider -> Which hashing algorithm will be used on the server side. Must match client side. Defaults to SHAMD5.
    * MaxQueryTimeoutLength -> The maximum time limit a query can exist before it becomes no longer authorized. Defaults to 15 minutes.
    * EndUserDateFormat -> The CultureInfo of the DateTime parse. Defaults to en-US.
    * Encoding -> Encoding format of the Key and Data. Defaults to ASCII encoding.
    * ParametersToIgnore -> Allows you to ignore certain parameters in the querystring. Defaults to none.