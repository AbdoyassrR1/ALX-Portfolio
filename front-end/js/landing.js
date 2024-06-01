const getStart = document.querySelector(".get-start");
const userId = localStorage.getItem("user_id");
const isLoggedIn = localStorage.getItem("isLoggedIn");

if (!isLoggedIn || !userId) {
  getStart.attributes.href.value = "./sign-in.html";
}
