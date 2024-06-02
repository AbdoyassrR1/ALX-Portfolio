import { getAllTasks } from "../functions/tasks.js";
import { taskDetails } from "./task-details.js";
import { createCardTask } from "../components/Card-Task.js";
import { noTasks } from "../components/No-Tasks.js";
import formateDate from "../functions/formate-date.js";
const category = document.querySelector("#category");
const priority = document.querySelector("#priority");
const statusSelect = document.querySelector("#status");
const search = document.querySelector("#search");
const filterBtn = document.querySelector("#filter-btn");
const taskContainer = document.getElementById("tasks-container");

getAllTasks("https://alx-portfolio-fy5s.onrender.com/tasks").then((task) => {
  if (task.length == 0) {
    noTasks(taskContainer);
  }
  task.forEach((task) => {
    const date = formateDate(task.updated_at);
    createCardTask(taskContainer, task, date);
  });
  const cards = document.querySelectorAll(".task-card");
  taskDetails(cards);
});

filterBtn.addEventListener("click", (e) => {
  e.preventDefault();
  const params = {
    category: category.value,
    priority: priority.value,
    status: statusSelect.value,
    search: search.value,
  };
  getAllTasks("https://alx-portfolio-fy5s.onrender.com/tasks", params).then(
    (task) => {
      if (task.length == 0) {
        noTasks(taskContainer);
        return;
      }

      taskContainer.innerHTML = "";
      task.forEach((task) => {
        const date = formateDate(task.updated_at);
        createCardTask(taskContainer, task, date);
      });
      const cards = document.querySelectorAll(".task-card");
      taskDetails(cards);
    }
  );
});
