import { handleSignPost } from "../functions/handle-sign.js";
import { validationForm } from "../functions/validation-form.js";
const userNameInput = document.getElementById("username");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const btnSignUp = document.getElementById("btn-sign");
const reloadIcon = document.getElementById("reload-icon");

btnSignUp.addEventListener("click", (e) => {
  const body = {
    username: userNameInput.value,
    email: emailInput.value,
    password: passwordInput.value,
  };
  const errors = validationForm(
    body,
    false,
    userNameInput,
    emailInput,
    passwordInput
  );
  if (errors.length > 0) {
    errors.forEach((error) => {
      alertify.set("notifier", "position", "top-right");
      alertify.error(error);
    });
    return;
  }
  userNameInput.classList.remove("animate__shakeX");
  emailInput.classList.remove("animate__shakeX");
  passwordInput.classList.remove("animate__shakeX");
  btnSignUp.setAttribute("disabled", "disabled");
  reloadIcon.classList.add("reload-icon");
  handleSignPost(e, `https://alx-portfolio-fy5s.onrender.com/signup`, body)
    .then(() => {
      window.location.href = "./sign-in.html";
    })
    .catch((error) => console.log(error));
});
