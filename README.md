My C implementation of a DNS resolver.

Follows https://implement-dns.wizardzines.com/

This is a tiny DNS resolver that implements a very limited subset of all the DNS stuff (there's a lot). The
aforementioned guide was a good help in structuring the code (which you will definitely see if you follow).
A lot of complication and cruff are added because of C and that I did not want to use too many builtins.

This is meant as a pedagogic exercise both for the writer and the reader. Nothing in this subset of feature is
inherently complicated, but in a C implementation a lot needs to line up to be functional. I tried to do my
best w.r.t safety, but I'm sure this is not safe. It was definitely interesting writing a bunch of vulnerabilities
and patch them up. There's an easy out of bound read that can be performed by a malicious actor on a vulnerable
program (it's identified in the code).

On the blog post, some exercises were left to the reader. I have not implemented them except for the recursion
attack. The DNS server exercise is fairly trivial since we can forward directly the messages we are receiving
to another server (unless we have a cache, then it gets interesting).

This is coded for linux, but I think with a few ifdefs and an init function you can get it working on windows.

Sample usage:

```shell
$ dns google.com
  Query for 'google.com': 172.217.13.206
```