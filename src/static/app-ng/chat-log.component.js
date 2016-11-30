(function(app) {
  app.ChatLogComponent = ng.core
  .Component({
    selector: 'chat-log',
    templateUrl: '/static/app/chat-log.component.html'
  })
  .Class({
    constructor: [function () {
      this.list = [];
      var user = new app.User(0, 'Test');
      this.list.push(new app.Message(user, "16:20:34", "Hello !"));
    }],
    addMessage: function (msg) {
      this.list.push(msg);
    }
  });
})(window.app || (window.app = {}));
