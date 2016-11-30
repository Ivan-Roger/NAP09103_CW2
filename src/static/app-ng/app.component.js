(function(app) {
  app.AppComponent =
    ng.core.Component({
      selector: 'my-app',
      template: '<chat-box></chat-box>'
    })
    .Class({
      constructor: function() {}
    });
})(window.app || (window.app = {}));
