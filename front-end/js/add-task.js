import { createTask } from "../functions/tasks.js";
const title = document.querySelector("#title");
const description = document.querySelector("#description");
const category = document.querySelector("#category");
const priority = document.querySelector("#priority");
const status = document.querySelector("#status");
const btnAddTask = document.querySelector("#btn-add-task");
const reloadIcon = document.querySelector("#btn-add-task #reload-icon");
console.log(reloadIcon);
const userId = localStorage.getItem("user_id");

btnAddTask.addEventListener("click", (e) => {
  e.preventDefault();
  const body = {
    title: title.value,
    description: description.value,
    category: category.value,
    priority: priority.value,
    status: status.value,
  };
  btnAddTask.setAttribute("disabled", "disabled");
  reloadIcon.classList.add("reload-icon");
  createTask(
    `https://alx-portfolio-fy5s.onrender.com/users/${userId}/tasks`,
    body
  )
    .then(() => {
      window.location.href = "./tasks.html";
    })
    .catch((error) => console.log(error));
});
