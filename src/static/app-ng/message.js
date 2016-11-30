(function(app) {
  app.Message = Message;
  function Message(sender, time, message) {
    this.sender = sender;
    this.time = time;
    this.message = message;
  }
})(window.app || (window.app = {}));
