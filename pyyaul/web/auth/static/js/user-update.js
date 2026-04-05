(function () {
  "use strict";

  var forms = document.querySelectorAll(".needs-validation");
  Array.prototype.slice.call(forms).forEach(function(form) {
    form.addEventListener("submit", function(event) {
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add("was-validated");
    }, false);
  });

  var phoneInput = document.getElementById("input_phone_sms");
  if (!phoneInput) {
    return;
  }
  phoneInput.addEventListener("input", function(event) {
    var parts = event.target.value.replace(/\D/g, "").match(/(\d{0,3})(\d{3})(\d{3})(\d{4})/);
    event.target.value = !parts[2] ? parts[1] : "+" + parts[1] + "-" + parts[2] + (!parts[3] ? "" : "-" + parts[3] + (!parts[4] ? "" : "-" + parts[4]));
  });
})();
