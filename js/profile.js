import { getUser, deleteUser, updateUser } from "../functions/user.js";
import {
  setUserInfo,
  editForm,
  verifyDeleteAccount,
} from "../components/User-Info.js";
const userId = localStorage.getItem("user_id");
const userContainer = document.querySelector("#user-container");
const userFormContainer = document.querySelector("#user-form-container");
getUser(`https://alx-portfolio-fy5s.onrender.com/users`, userId)
  .then((user) => {
    setUserInfo(userContainer, user);
    return user;
  })
  .then((user) => {
    const editInfo = document.querySelector("#edit-info");
    editInfo.addEventListener("click", () => {
      document.body.classList.add("blur");
      editForm(userFormContainer);
      const cancelBtn = document.querySelector("#cancel");
      const saveBtn = document.querySelector("#save");
      cancelBtn.addEventListener("click", () => {
        document.body.classList.remove("blur");
        userFormContainer.innerHTML = "";
      });
      saveBtn.addEventListener("click", () => {
        const username = document.querySelector("#username").value;
        const email = document.querySelector("#email").value;
        username &&
          updateUser(`https://alx-portfolio-fy5s.onrender.com/users`, userId, {
            username,
          }).then(() => {
            window.location.reload();
          });
        email &&
          updateUser(`https://alx-portfolio-fy5s.onrender.com/users`, userId, {
            email,
          }).then(() => {
            window.location.reload();
          });
      });
    });
    return user;
  })
  .then(() => {
    const deleteUserBtn = document.querySelector("#delete-user");
    deleteUserBtn?.addEventListener("click", () => {
      document.body.classList.add("blur");
      verifyDeleteAccount(userFormContainer);
      const cancelBtn = document.querySelector("#cancel");
      const deleteBtn = document.querySelector("#delete");
      cancelBtn.addEventListener("click", () => {
        document.body.classList.remove("blur");
        userFormContainer.innerHTML = "";
      });
      deleteBtn.addEventListener("click", () => {
        deleteUser(`https://alx-portfolio-fy5s.onrender.com/users`, userId)
          .then(() => {
            localStorage.clear();
            window.location.href = "./index.html";
          })
          .catch((err) => {
            console.log(err);
          });
      });
    });
  });
