// RethinkDB Model
var thinky = require('thinky')();

var type = thinky.type;

var User = thinky.createModel("User", {
      id: String,
      timestamp: String,
      shost: String,
      sIP: String,
      dIP: String,
      sPort: String,
      dPort: String,
      protocol: String,
      login: String,
      password: String
});

module.exports = User;
