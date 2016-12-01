// Client keys
var keys = {
  server: null,
  private: null,
  public: null,
  contacts: {}
}
var password = null

var userID = null;
var pseudo = null;
var token = null;
var socket = null;


// class EncryptedKey:
var EncryptedKey = function(value) {
  var obj = {};
  obj._value = value;
  obj._encrypted = true;
  obj.decrypt = function (passphrase, callback) {
    if (obj.isDecrypted()) {
      if (callback) callback();
      return;
    }
    openpgp.decryptKey({privateKey: obj._value, passphrase: passphrase}).then(function (unlocked) {
      obj._value = unlocked.key;
      obj._decrypted = true;
      console.log("PrivK: Decrypted private key !");
      if (callback) callback(this);
    });
  }
  obj.isDecrypted = function () {
    return obj._decrypted;
  }
  obj.value = function () {
    if (obj.isDecrypted())
      return obj._value;
    return null;
  }
  return obj;
}

function request(method, url, callback, data = null) {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {
      if (this.readyState == 4) {
        if (this.status == 200) {
          var res = JSON.parse(this.responseText);
          callback(true, res);
        } else {
          try {
            var res = JSON.parse(this.responseText);
            callback(false, res);
          } catch (error) {
            callback(false, null);
          }
        }
      }
  };
  xhr.open(method, url);

  if (method!='GET')
    xhr.setRequestHeader("Content-Type", "application/json");

  if (data != null)
    xhr.send(data);
  else
    xhr.send();
}

var msgList = document.querySelector("#app-msgList");
var msgTemplate = document.querySelector("#app-template-chatMsg");

// --- INIT ---
openpgp.initWorker({ path:'/static/js/openpgp.worker.min.js' });

/* // KEYS
var pubkeyTxt = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v2.3.5\nComment: http://openpgpjs.org\n\n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\n=F6V4\n-----END PGP PUBLIC KEY BLOCK-----";
var privkeyTxt = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: OpenPGP.js v2.3.5\nComment: http://openpgpjs.org\n\n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\n=VO1B\n-----END PGP PRIVATE KEY BLOCK-----";
keys.public = openpgp.key.readArmored(pubkeyTxt).keys[0];
keys.private = EncryptedKey(openpgp.key.readArmored(privkeyTxt).keys[0]);
//*/

// 'ThatiSREALLYaGooDSecret'
function openChat() {
  request('GET', "/api/users/"+userID+"/contacts?token="+token, function(success, data) {
    if (success) {
      console.log("CONTACTS > Found "+data.contacts.length+" contacts.");
      var list = document.querySelector("#app-chat .app-contactList");
      var template = document.querySelector("#app-template-contactListItem");
      data.contacts.forEach(function (c) {
        var elem = template.cloneNode(true);
        elem.querySelector("h3").innerHTML = c.pseudo;
        elem.querySelector("p").innerHTML = (c.tags!=null?c.tags:'No description registered');

        if (c.isOnline)
          elem.classList.add('user-online');
        else {
          var lastSeen = new Date(c.lastOnline*1000);
          elem.querySelector("i").innerHTML = lastSeen.toISOString().replace('T',' ').split('.')[0];
        }

        // elem.addEventListener('click', openDiscussion); // Register the listener
        list.appendChild(elem);
      });
    } else { // ERROR
      if (data==null)
        console.warn("CONTACTS > "+this.status, this.responseText);
      else
        console.warn("CONTACTS > "+data.error, data.message);
    }
  });

  // keys.server = openpgp.key.readArmored(data.server_key).keys[0];
  // keys.public = openpgp.key.readArmored(data.public_key).keys[0];
  // keys.private = EncryptedKey(openpgp.key.readArmored(data.private_key).keys[0]);
  // keys.private.decrypt(password, function () {
  //
  // });
}
function startSocket() {
  socket = io.connect('http://' + document.domain + ':' + location.port);
  socket.on('connect', function() {
    console.log("SOCKET: Connected!");
    socket.emit('init', {state: 'AUTH', userID: userID, pseudo: pseudo, token: token});
    keys.private.decrypt('ThatiSREALLYaGooDSecret', function () {
      socket.emit('init', {state: 'DONE', token: token});
    });
  });

  /*options = { // input as String (or Uint8Array)
    data: "Bonjour marc dupond !!!",
    publicKeys: keys.public,  // for encryption
  };

  openpgp.encrypt(options).then(function(ciphertext) {
    encryptedMsg = ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
    socket.emit('encMessage', {token: token, message: encryptedMsg});
  });*/

  socket.on('encMessage', function(data) {
    console.log("Decrypting message from ("+data.pseudo+"["+data.userID+"])");
    var date = new Date(); // Parse time in msg

    options = {
      message: openpgp.message.readArmored(data.message),     // parse armored message
      privateKey: keys.private.value() // for decryption
    };

    openpgp.decrypt(options).then(function(plaintext) {
      msg = msgTemplate.cloneNode(true);
      msg.querySelector(".app-chatMsgUser .app-msgUserName").innerHTML = data.pseudo;
      msg.querySelector(".app-chatMsgContent").innerHTML = plaintext.data;
      msg.querySelector(".app-chatMsgInfos .app-msgInfosTime").innerHTML = date.toISOString().split('T')[1].split('.')[0];
      msgList.appendChild(msg)
      console.log("Message :",plaintext.data);
    });
  });
}

// ------------------------------- LOGIN -------------------------------

function login(email, password) {
  request('POST', "/api/login", function(success,data){
    if (success) {
      userID = data.userID;
      pseudo = data.pseudo;
      token = data.token;
      document.querySelector("#app-login-email").value = "";
      console.log("TOKEN > "+token);
      document.querySelector("#app-login").classList.add('hide');
      document.querySelector("#app-chat").classList.remove('hide');
      openChat();
    } else {
      if (data==null) {
        console.warn("LOGIN > "+res.error, res.message);
        document.querySelector("#app-login-info").innerHTML = res.message;
      } else {
        console.warn("LOGIN > "+this.status, this.responseText);
        document.querySelector("#app-login-info").innerHTML = "Error when loggin in. Retry";
      }
      setTimeout(function () {
        document.querySelector("#app-login-info").innerHTML = "Please login :";
      },2500);
    }
  }, '{"email": "'+email+'", "password": "'+password+'"}');
  document.querySelector("#app-login-info").innerHTML = "Logging in ...";
}

document.querySelector("#app-login-BTN").addEventListener('click', function () {
  var email = document.querySelector("#app-login-email").value;
  password = document.querySelector("#app-login-pw").value;
  login(email, password); // TODO: Hash password !!!
});
