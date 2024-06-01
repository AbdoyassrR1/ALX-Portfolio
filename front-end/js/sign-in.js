import { handleSignPost } from "../functions/handle-sign.js";
import { validationForm } from "../functions/validation-form.js";
const userNameEmailInput = document.getElementById("username-email");
const passwordInput = document.getElementById("password");
const btnSignIn = document.getElementById("btn-sign");
const reloadIcon = document.getElementById("reload-icon");

btnSignIn.addEventListener("click", (e) => {
  const body = {
    email: userNameEmailInput.value,
    password: passwordInput.value,
  };
  const errors = validationForm(body, true, userNameEmailInput, passwordInput);
  console.log(errors);
  if (errors.length > 0) {
    errors.forEach((error) => {
      alertify.set("notifier", "position", "top-right");
      alertify.error(error);
    });
    return;
  }
  userNameEmailInput.classList.remove("animate__shakeX");
  passwordInput.classList.remove("animate__shakeX");
  btnSignIn.setAttribute("disabled", "disabled");
  reloadIcon.classList.add("reload-icon");
  handleSignPost(e, `https://alx-portfolio-fy5s.onrender.com/signin`, body)
    .then(() => {
      window.location.href = "../index.html";
    })
    .catch((error) => console.log(error));
});
