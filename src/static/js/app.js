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
            console.log(error);
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
var msgTemplate = document.querySelector("#app-templates .app-chatMsg");

// --- INIT ---
openpgp.initWorker({ path:'/static/js/openpgp.worker.min.js' });

/* // KEYS
keys.public = openpgp.key.readArmored(pubkeyTxt).keys[0];
keys.private = EncryptedKey(openpgp.key.readArmored(privkeyTxt).keys[0]);
//*/

// 'ThatiSREALLYaGooDSecret'
function openChat() {
  request('GET', "/api/users/"+userID+"/contacts?token="+token, function(success, data) {
    if (success) {
      console.log("CONTACTS > Found "+data.contacts.length+" contacts.");
      var list = document.querySelector("#app-chat .app-contactList");
      var template = document.querySelector("#app-templates .app-contactListItem");
      data.contacts.forEach(function (c) {
        var elem = template.cloneNode(true);
        elem.querySelector("h3").innerHTML = c.pseudo;
        elem.querySelector("p").innerHTML = (c.tags!=null?c.tags:'No description registered');
        elem.setAttribute('data-userID', c.id);

        if (c.isOnline) {
          elem.classList.add('user-online');
        } else {
          var lastSeen = new Date(c.lastOnline*1000);
          elem.querySelector("i .lastSeen").innerHTML = lastSeen.toISOString().replace('T',' ').split('.')[0];
        }
        elem.addEventListener('click', function (e) { // Register the listener
          if (elem.classList.contains('user-online')) openDiscussion(c.id, e.target);
        });

        list.appendChild(elem);
      });

      startSocket(); // Until keys are working
      // keys.server = openpgp.key.readArmored(data.server_key).keys[0];
      // keys.public = openpgp.key.readArmored(data.public_key).keys[0];
      // keys.private = EncryptedKey(openpgp.key.readArmored(data.private_key).keys[0]);
      // keys.private.decrypt(password, function () {
        // startSocket();
      // });
    } else { // ERROR
      if (typeof data=="string")
        console.warn("CONTACTS > ", data);
      else
        console.warn("CONTACTS > "+data.error, data.message);
    }
  });
}

function openDiscussion(recipientID) {
  var prevRecipient = document.querySelector("#app-chat .app-chatContacts .app-contactListItem.active");
  if (prevRecipient!=null) prevRecipient.classList.remove('active');
  document.querySelector("#app-chat .app-chatBox").classList.remove('noDiscussionOpened');
  document.querySelector("#app-chat .app-chatBox").classList.add('loading');
  request('GET', '/api/users/'+recipientID+'/public-key?token='+token, function (success, data) {
    if (success) {
      document.querySelector("#app-chat .app-chatBox").classList.remove('loading');
      document.querySelector("#app-chat .app-chatContacts .app-contactListItem[data-userID='"+recipientID+"']").classList.add('active');
      // document.querySelector("#app-chat .app-chatBox .app-chatBoxTitle-with").innerHTML = recipient.pseudo;
      socket.emit('ask', {user: recipientID, token: token});
    } else {
      document.querySelector("#app-chat .app-chatBox").classList.remove('loading');
      document.querySelector("#app-chat .app-chatBox").classList.add('noDiscussionOpened');
      if (typeof data=="string") {
      } else {
      }
    }
  });
}

function startSocket() {
  socket = io.connect('//'+document.domain+':'+location.port+'/user-'+userID);
  socket.on('connect', function() {
    console.log("SOCKET: Connected!");
    socket.emit('init', {userID: userID, pseudo: pseudo, token: token});
  });

  socket.on('accept', function(data) {
    console.log("SOCKET: Accepted dicussion "+data.discussion.id);
    socket.emit('join', {discussion: data.discussion.id, token: token});
  });

  socket.on('message', function(data) {
    console.log("Decrypting message from ("+data.pseudo+"["+data.userID+"])");
    var date = new Date(data.time*1000);

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

function sendMessage(recID, msg) {
  options = { // input as String (or Uint8Array)
    data: msg,
    publicKeys: keys.contacts[recID].public,  // TODO: get public key of recipient
  };

  openpgp.encrypt(options).then(function(ciphertext) {
    encryptedMsg = ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
    socket.emit('message', {token: token, message: encryptedMsg, 'recipient': recID});
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
      if (typeof data=="string") {
        console.warn("LOGIN > ", data);
        document.querySelector("#app-login-info").innerHTML = "Error when logging in. Retry";
      } else {
        console.warn("LOGIN > "+data.error, data.message);
        document.querySelector("#app-login-info").innerHTML = data.message;
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
