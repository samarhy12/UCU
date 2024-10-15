// static/js/main.js

document.addEventListener("DOMContentLoaded", function () {
  // Form validation
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    form.addEventListener("submit", function (event) {
      if (!validateForm(this)) {
        event.preventDefault();
      }
    });
  });

  // Add more event listeners and functions as needed
});

function validateForm(form) {
  let isValid = true;
  const inputs = form.querySelectorAll("input, textarea");

  inputs.forEach((input) => {
    if (input.hasAttribute("required") && !input.value.trim()) {
      showError(input, "This field is required");
      isValid = false;
    } else {
      clearError(input);
    }

    if (input.type === "email" && !isValidEmail(input.value)) {
      showError(input, "Please enter a valid email address");
      isValid = false;
    }
  });

  return isValid;
}

function showError(input, message) {
  const errorElement = input.nextElementSibling;
  if (errorElement && errorElement.classList.contains("error-message")) {
    errorElement.textContent = message;
  } else {
    const error = document.createElement("div");
    error.className = "error-message";
    error.textContent = message;
    input.parentNode.insertBefore(error, input.nextSibling);
  }
  input.classList.add("error");
}

function clearError(input) {
  const errorElement = input.nextElementSibling;
  if (errorElement && errorElement.classList.contains("error-message")) {
    errorElement.remove();
  }
  input.classList.remove("error");
}

function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// Add more helper functions as needed

// Example of a function to handle AJAX requests
function sendAjaxRequest(url, method, data, successCallback, errorCallback) {
  const xhr = new XMLHttpRequest();
  xhr.open(method, url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.onreadystatechange = function () {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      if (xhr.status === 200) {
        successCallback(JSON.parse(xhr.responseText));
      } else {
        errorCallback(xhr.status, xhr.statusText);
      }
    }
  };
  xhr.send(JSON.stringify(data));
}

// Add this to your static/js/main.js file

function checkPasswordStrength(password) {
  let strength = 0;
  if (password.length >= 8) strength += 1;
  if (password.match(/[a-z]+/)) strength += 1;
  if (password.match(/[A-Z]+/)) strength += 1;
  if (password.match(/[0-9]+/)) strength += 1;
  if (password.match(/[$@#&!]+/)) strength += 1;

  return strength;
}

document.addEventListener("DOMContentLoaded", function () {
  const passwordInput = document.querySelector("#password");
  const strengthMeter = document.querySelector("#password-strength-meter");
  const strengthText = document.querySelector("#password-strength-text");

  if (passwordInput && strengthMeter && strengthText) {
    passwordInput.addEventListener("input", function () {
      const strength = checkPasswordStrength(this.value);
      strengthMeter.value = strength;

      let strengthLabel = "";
      switch (strength) {
        case 0:
        case 1:
          strengthLabel = "Weak";
          strengthText.style.color = "red";
          break;
        case 2:
        case 3:
          strengthLabel = "Moderate";
          strengthText.style.color = "orange";
          break;
        case 4:
        case 5:
          strengthLabel = "Strong";
          strengthText.style.color = "green";
          break;
      }
      strengthText.textContent = `Password strength: ${strengthLabel}`;
    });
  }
});
