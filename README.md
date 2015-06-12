Wall of Sheep
=============
```
 _       _____    __    __       ____  ______   _____ __  __________________
| |     / /   |  / /   / /      / __ \/ ____/  / ___// / / / ____/ ____/ __ \
| | /| / / /| | / /   / /      / / / / /_      \__ \/ /_/ / __/ / __/ / /_/ /
| |/ |/ / ___ |/ /___/ /___   / /_/ / __/     ___/ / __  / /___/ /___/ ____/
|__/|__/_/  |_/_____/_____/   \____/_/       /____/_/ /_/_____/_____/_/

```

[![Join the chat at https://gitter.im/John-Lin/wallofsheep](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/John-Lin/wallofsheep?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

The Wall of Sheep is dedicated to network security research and we make use of a powerful API provided by [RethinkDB](http://www.rethinkdb.com/), [Firebase](https://www.firebase.com/) to store and sync data in realtime.

Without SSL/TLS, your password is just like streaking. Therefore, we recommend that service provider in the list should secure their websites with HTTPS.

You can check out the [demo page](https://amber-inferno-5029.firebaseapp.com).
The circle symbolizes that the status of sniffer program. Green is online, otherwise offline.

We built sniffer in two languages `Python` and `Node.js`. The `Node.js` version support on OSX and Linux. Unfortunately, The `Python` version only support on Linux.

New implementation in Node.js
=============

**[April 18, 2015 Updated]** Add `Node.js` sniffer implementation. Now OSX user can play with it. :laughing:

We believe that using JavaScript is more efficient. Please refer to [Why capture packets in JavaScript?](https://github.com/mranney/node_pcap#why-capture-packets-in-javascript)

In simple terms

- Event-based.
- Handling binary data is fast and efficient.
- Good HTTP parser.

Installation
=============

Here is installation method.

Using brew install `Node.js`, `npm` and `rethinkdb` (option).

```
$ brew update
$ brew install node
$ brew install npm
$ brew install rethinkdb
```

Clone the repo and change directory to `nodejs` folder.

```
$ git clone git@github.com:John-Lin/wallofsheep.git
```

Packet capturing depends on [mranney/node_pcap](https://github.com/mranney/node_pcap) and save data to RethinkDB using [neumino/thinky](https://github.com/neumino/thinky) (option) you can use `npm` to get these packages.

```
$ npm install
```

That's it.

Basic usage
=============

Two ways to use

Not saving the credentials. Start the `sniffer` with sudo

```
john at JohnsMacBook-Air in ~/Repository/wallofsheep/nodejs (master●●)
$ sudo node sniffer.js -i en0
[-] Loading RethinkDB module.
  _       _____    __    __       ____  ______   _____ __  __________________
| |     / /   |  / /   / /      / __ \/ ____/  / ___// / / / ____/ ____/ __ \
| | /| / / /| | / /   / /      / / / / /_      \__ \/ /_/ / __/ / __/ / /_/ /
| |/ |/ / ___ |/ /___/ /___   / /_/ / __/     ___/ / __  / /___/ /___/ ____/
|__/|__/_/  |_/_____/_____/   \____/_/       /____/_/ /_/_____/_____/_/
[*] Using interface: en0
[192.168.0.16:61881 -> 140.***.**.***:80] Account: hello@gmail.com
[192.168.0.16:61881 -> 140.***.**.***:80] Password: thisispassword
```


Saving credentials in RethinkDB need `-s` option.

First, start the RethinkDB server like this:

```
$ rethinkdb
info: Creating directory 'rethinkdb_data'
info: Listening for intracluster connections on port 29015
info: Listening for client driver connections on port 28015
info: Listening for administrative HTTP connections on port 8080
info: Server ready
```

Second, open a new terminal and start the `sniffer` with sudo

```
john at JohnsMacBook-Air in ~/Repository/wallofsheep/nodejs (master●●)
$ sudo node sniffer.js -i en0 -s
[-] Loading RethinkDB module.
  _       _____    __    __       ____  ______   _____ __  __________________
| |     / /   |  / /   / /      / __ \/ ____/  / ___// / / / ____/ ____/ __ \
| | /| / / /| | / /   / /      / / / / /_      \__ \/ /_/ / __/ / __/ / /_/ /
| |/ |/ / ___ |/ /___/ /___   / /_/ / __/     ___/ / __  / /___/ /___/ ____/
|__/|__/_/  |_/_____/_____/   \____/_/       /____/_/ /_/_____/_____/_/
[*] Using interface: en0
[192.168.0.16:61881 -> 140.***.**.***:80] Account: hello@gmail.com
[192.168.0.16:61881 -> 140.***.**.***:80] Password: thisispassword
```


Work in progress
================
- [x] Support [RethinkDB](http://www.rethinkdb.com/) provided push/sync data in realtime.
- [x] Parsing user/password in IMAP protocol.
- [X] Parsing user/password in POP3 protocol.
- [ ] A new Web interface for showing off rely on [RethinkDB](http://www.rethinkdb.com/).
- [ ] Any protocol not encrypted (e.g., telnet, irc etc.)


Screenshot
===========
![wallofsheep](/screenshot/screenshot.jpeg?raw=true "Wall of Sheep")


Contributing
===========
Your contribution is welcome :octocat: ! follow these steps:

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
