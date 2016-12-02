// Client keys
var keys = {
  private: null,
  public: null,
  contacts: {}
}
var password = null

var userID = null;
var pseudo = null;
var token = null;
var socket = null;
var contacts = null;
var currDisc = null;

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
            callback(false, "ERROR_"+this.status);
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

var msgList = document.querySelector("#app-chat .app-msgList");
var msgTemplate = document.querySelector("#app-templates .app-chatMsg");

// --- INIT ---
openpgp.initWorker({ path:'/static/js/openpgp.worker.min.js' });

function openChat() {
  request('GET', "/api/users/"+userID+"/contacts?token="+token, function(success, data) {
    if (success) {
      console.log("CONTACTS > Found "+data.contacts.length+" contacts.");
      var list = document.querySelector("#app-chat .app-contactList");
      var template = document.querySelector("#app-templates .app-contactListItem");
      contacts = {};
      data.contacts.forEach(function (c) {
        contacts[c.id] = c;
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
          if (elem.classList.contains('user-online') && !elem.classList.contains('active'))
          askDiscussion(c.id);
        });

        list.appendChild(elem);
      });

      // keys.server = openpgp.key.readArmored(data.server_key).keys[0];
      request('GET', "/api/users/"+userID+"/public-key?token="+token, function (success, data) {
        if (success) {
          var armoredPubKeys = openpgp.key.readArmored(data.public_key);
          if (armoredPubKeys.err!=undefined && armoredPubKeys.err.length>0) {
            console.log("Error when reading public key: "+armoredPubKeys.err[0].message,armoredPubKeys.err);
          } else {
            keys.public = armoredPubKeys.keys[0];
            console.log("Public key:",keys.public);
            request('GET', "/api/users/"+userID+"/private-key?token="+token, function (success, data) {
              if (success) {
                var armoredPrivKey = openpgp.key.readArmored(data.private_key);
                if (armoredPrivKey.err!=undefined && armoredPrivKey.err.length>0) {
                  console.log("Error when reading private key: "+armoredPrivKey.err[0].message,armoredPrivKey.err);
                } else {
                  keys.private = armoredPrivKey.keys[0];
                  keys.private.decrypt(password);
                  console.log("Private key:",keys.private);
                  startSocket();

                  // keys.private = EncryptedKey(openpgp.key.readArmored(data.private_key).keys[0]);
                  // keys.private.decrypt(password, function () {
                  //   startSocket();
                  // });
                }
              } else { // ERROR
                console.warn("PRIVKEY > "+data);
              }
            });
          }
        } else { // ERROR
          console.warn("PUBKEY > "+data);
        }
      });
    } else { // ERROR
      if (typeof data=="string")
        console.warn("CONTACTS > ", data);
      else
        console.warn("CONTACTS > "+data.error, data.message);
    }
  });
}

function askDiscussion(recipientID) {
  var prevRecipient = document.querySelector("#app-chat .app-chatContacts .app-contactListItem.active");
  if (prevRecipient!=null) prevRecipient.classList.remove('active');
  document.querySelector("#app-chat .app-chatBox").classList.remove('noDiscussionOpened');
  document.querySelector("#app-chat .app-chatBox").classList.add('loading');
  socket.emit('ask', {user: recipientID, message: 'I want to talk', token: token});
}

function openDiscussion(disc) {
  console.log("Opening discussion !",disc);
  var prevRecipient = document.querySelector("#app-chat .app-chatContacts .app-contactListItem.active");
  if (prevRecipient!=null) prevRecipient.classList.remove('active');
  document.querySelector("#app-chat .app-chatBox").classList.remove('noDiscussionOpened');
  document.querySelector("#app-chat .app-chatBox").classList.add('loading');
  document.querySelector("#app-chat .app-chatInput").classList.remove('hide');
  msgList.innerHTML="";
  if (disc.userA==userID) recipient = disc.userB;
  else recipient = disc.userA;
  console.log("Recipient is "+recipient, contacts[recipient]);
  request('GET', '/api/users/'+recipient+'/public-key?token='+token, function (success, data) {
    if (success) {
      currDisc = disc;
      keys.contacts[recipient] = openpgp.key.readArmored(data.public_key).keys[0];
      // TODO check that key is OK
      document.querySelector("#app-chat .app-chatBox").classList.remove('loading');
      document.querySelector("#app-chat .app-chatContacts .app-contactListItem[data-userID='"+recipient+"']").classList.add('active');
      document.querySelector("#app-chat .app-chatBox .app-chatBoxTitle-with").innerHTML = contacts[recipient].pseudo;
    } else {
      document.querySelector("#app-chat .app-chatBox").classList.remove('loading');
      document.querySelector("#app-chat .app-chatBox").classList.add('noDiscussionOpened');
      console.warn("Contact PUBKEY >",data); // TODO Display error
    }
  });
}

function startSocket() {
  socket = io.connect('//'+document.domain+':'+location.port);
  socket.on('connect', function() {
    console.log("SOCKET: Connected!");
    socket.emit('init', {userID: userID, pseudo: pseudo, token: token});
  });

  socket.on('online', function(data) {
    console.log("SOCKET: Contact online.",data.user);
    contacts[data.user.id] = data.user;
    var contactElem = document.querySelector("#app-chat .app-chatContacts .app-contactListItem[data-userID='"+data.user.id+"']");
    contactElem.classList.add('user-online');
    contactElem.querySelector("h3").innerHTML = data.user.pseudo;
  });

  socket.on('offline', function(data) {
    console.log("SOCKET: Contact offline.",data.user);
    contacts[data.user].isOnline = false;
    contacts[data.user].lastSeen = data.time;
    var contactElem = document.querySelector("#app-chat .app-chatContacts .app-contactListItem[data-userID='"+data.user+"']");
    contactElem.classList.remove('user-online');
    if (contactElem.classList.contains('active')) {
      logMessage({sender: data.user, time: data.time, message: 'disconnected !'}, true);
      document.querySelector("#app-chat .app-chatInput").classList.add('hide');
      setTimeout(function() {
        contactElem.classList.remove('active');
        document.querySelector("#app-chat .app-chatBox").classList.remove('loading');
        document.querySelector("#app-chat .app-chatBox").classList.add('noDiscussionOpened');
      }, 5000);
    }
  });

  socket.on('accept', function(data) { // My contact accpted to talk with me
    console.log("SOCKET: Accepted discussion "+data.discussion.id);
    socket.emit('join', {discussion: data.discussion.id, token: token});
    openDiscussion(data.discussion);
  });

  socket.on('ask', function(data) { // Someone asked to talk with me
    console.log("SOCKET: Discussion request "+data.discussion.id);
    socket.emit('accept', {discussion: data.discussion.id, token: token});
    openDiscussion(data.discussion);
  });

  socket.on('join', function(data) {
    if (data.sender!=userID) console.log("SOCKET: Discussion joined by "+contacts[data.sender].pseudo, data.discussion.id);
    else console.log("SOCKET: Discussion joined by "+pseudo, data.discussion.id);
    logMessage(data, true);
  });

  socket.on('message', function(data) {
    console.log("Decrypting message from ("+data.sender+")");
    logMessage(data);
  });
}

function sendMessage(msg) {
  if (currDisc.userA==userID) recID = currDisc.userB;
  else recID = currDisc.userA;
  options = { // input as String (or Uint8Array)
    data: msg,
    publicKeys: keys.contacts[recID],  // TODO: Check public key of recipient
  };
  openpgp.encrypt(options).then(function(ciphertext) {
    encryptedMsg = ciphertext.data; // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'
    socket.emit('message', {discussion: currDisc.id, sender: userID, message: encryptedMsg, token: token});
    logMessage({discussion: currDisc.id, sender: userID, message: msg, time: date.now()/1000});
  });
}

function logMessage(msg, system = false) {
  if (msg.encrypted) {
    options = {
      message: openpgp.message.readArmored(msg.message),     // parse armored message
      privateKey: keys.private // for decryption
    };
    openpgp.decrypt(options).then(function(plaintext) {
      msg.message = plaintext.data;
      msg.encrypted = false;
      logMessage(msg, system);
    });
    return;
  }
  var date = new Date(msg.time*1000);
  var msgElem = msgTemplate.cloneNode(true);
  msgElem.querySelector(".app-msgInfosTime").innerHTML = date.toISOString().split('T')[1].split('.')[0];
  if (msg.sender==userID) msgElem.querySelector(".app-msgUserName").innerHTML = pseudo;
  else msgElem.querySelector(".app-msgUserName").innerHTML = contacts[msg.sender].pseudo;
  msgElem.querySelector(".app-chatMsgContent").innerHTML = msg.message;
  if (system) msgElem.classList.add('systemMsg');
  msgList.appendChild(msgElem);
  if (msg.sender==userID) console.log("Message ("+pseudo+"):",msg.message);
  else console.log("Message ("+contacts[msg.sender].pseudo+"):",msg.message);
}

// ------------------------------- LOGIN -------------------------------

function login(email, password) {
  request('POST', "/api/login", function(success,data){
    if (success) {
      userID = data.userID;
      pseudo = data.pseudo;
      token = data.token;
      document.querySelector("#app-login-email").value = "";
      document.querySelector("#app-login-pw").value = "";
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

function logout() {
  document.querySelector("#app-chat").classList.add('hide');
  document.querySelector("#app-chat .app-contactList").innerHTML="";
  document.querySelector("#app-chat .app-chatBox").classList.remove('loading');
  document.querySelector("#app-chat .app-chatBox").classList.add('noDiscussionOpened');
  userID = null;
  pseudo = null;
  token = null;
  contacts = null;
  currDisc = null;
  socket.disconnect();
  socket = null;
  keys.private = null;
  keys.public = null;
  keys.contacts = {};
  document.querySelector("#app-login-info").innerHTML = "Please login :";
  document.querySelector("#app-login").classList.remove('hide');
}

document.querySelector("#app-login-BTN").addEventListener('click', function () {
  var email = document.querySelector("#app-login-email").value;
  password = document.querySelector("#app-login-pw").value;
  login(email, password); // TODO: Hash password !!!
});

document.querySelector("#app-chat .app-chatInput .app-chatInputSub").addEventListener('click', function () {
  var elem = document.querySelector("#app-chat .app-chatInput .app-chatInputMsg");
  sendMessage(elem.value);
  elem.value = "";
});
