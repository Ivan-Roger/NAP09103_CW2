(function(app) {
  app.User = User;
  function User(id, name, status) {
    this.id = id;
    this.name = name;
    this.status = status;
  }
  User.setStatus = function(status) {
    this.status = status;
  }
})(window.app || (window.app = {}));
