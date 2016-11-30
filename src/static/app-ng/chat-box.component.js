(function(app) {
  app.ChatBoxComponent = ng.core
    .Component({
      selector: 'chat-box',
      templateUrl: '/static/app/chat-box.component.html',
      queries: {
        'chatLog': new app.ChatLogComponent(app.ChatBoxComponent)
      },
      directives: [ app.ChatLogComponent ]
    })
    .Class({
      constructor: [function() {
        // Nothing yet.
        this.chatLog = ng.core.ViewChild('chatLog','ChatLogComponent', this);
      }],
      sendMessage: function() {
        console.log("sendMessage!");
        this.chatLog.addMessage(new app.Message(new app.User(1, "Ivan"), "17:13:49", "Hey there. What's up ?"));
      }
    });
})(window.app || (window.app = {}));
