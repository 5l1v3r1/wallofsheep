Wall of Sheep
=============

[![Join the chat at https://gitter.im/John-Lin/wallofsheep](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/John-Lin/wallofsheep?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

The Wall of Sheep is dedicated to network security research and we make use of a powerful API provided by [Firebase](https://www.firebase.com/) to store and sync data in realtime.

Without SSL/TLS, your password is just like streaking. Therefore, we recommend that service provider in the list should secure their websites with HTTPS.

You can check out the [demo page](https://amber-inferno-5029.firebaseapp.com).
The circle symbolizes that the status of sniffer program. Green is online, otherwise offline.

New implementation in Node.js
=============

**[April 18, 2015 Updated]** Add `Node.js` sniffer implementation. Now OSX user can play with it. :laughing:

We believe that using Javascript is more efficient. Please refer to [Why capture packets in JavaScript?](https://github.com/mranney/node_pcap#why-capture-packets-in-javascript)

In simple terms

- Event-based.
- Handling binary data is fast and efficient.
- Good HTTP parser.

Here is installation method.

Using brew install `Node.js` and `npm`.

```
$ brew update
$ brew install node
$ brew install npm
```

Clone the repo and change directory to nodejs folder.

```
$ git clone git@github.com:John-Lin/wallofsheep.git
```

packet capturing depend on [node_pcap](https://github.com/mranney/node_pcap) using `npm` to get `node_pcap`.

```
$ npm install pcap
```

That's it. Basic usage

```
john at JohnsMacBook-Air in ~/Repository/wallofsheep/nodejs (master●●)
$ sudo node sniffer.js en0
[*] Using interface: en0
[192.168.0.16:61881 -> 140.***.**.***:80] Account: hello@gmail.com
[192.168.0.16:61881 -> 140.***.**.***:80] Password: thisispassword
```


Work in progress
================

The branch `use-rethinkdb` use loacal database which is [RethinkDB](http://www.rethinkdb.com/) also provided push data in realtime.


Screenshot
===========
![wallofsheep](/screenshot/screenshot.jpeg?raw=true "Wall of Sheep")


Contributing
===========
- Fork this project.
- Create a branch (git checkout -b my_feature_patch)
- Commit your changes (git commit -am "Added Something Feature")
- Push to the branch (git push origin my_feature_patch)
- Open a Pull Request
- Wait for merge :smile:


Contributors
===========
- [John-Lin](https://github.com/John-Lin)
- [lockys](https://github.com/lockys)
