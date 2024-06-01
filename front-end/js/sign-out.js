import { handleSignGet } from "../functions/handle-sign.js";
const btnSignOut = document.getElementById("btn-sign-out");
const reloadIcon = document.getElementById("reload-icon");
const nav = document.getElementById("nav");
const user = document.getElementById("user");
const userId = localStorage.getItem("user_id");
const isLoggedIn = localStorage.getItem("isLoggedIn");

if (isLoggedIn || userId) {
  nav.style.display = "none";
  user.style.display = "flex";
} else {
  nav.style.display = "flex";
  user.style.display = "none";
}

btnSignOut.addEventListener("click", (e) => {
  btnSignOut.setAttribute("disabled", "disabled");
  reloadIcon.classList.add("reload-icon");
  handleSignGet(e, `https://alx-portfolio-fy5s.onrender.com/signout`, userId)
    .then(() => {
      window.location.href = "../index.html";
    })
    .catch((error) => console.log(error));
});
