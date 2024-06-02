import { getOneTask } from "../functions/tasks.js";
import { getOneUser } from "../functions/user.js";
import { deleteTask, updateTask } from "../functions/tasks.js";
import { createTaskDetails } from "../components/Create-Task-Details.js";
const taskDetailsContainer = document.querySelector("#task-details");

const closeTaskDetails = (element) => {
  element.addEventListener("click", () => {
    document.body.classList.remove("blur");
    taskDetailsContainer.innerHTML = "";
  });
};

const handleDeleteTask = (element) => {
  element.addEventListener("click", () => {
    const taskId = element.closest(".card-details").id;
    deleteTask("https://alx-portfolio-fy5s.onrender.com/tasks", taskId).then(
      () => {
        window.location.reload();
      }
    );
  });
};

const handleUpdateTask = (actionElement, ...inputs) => {
  const [title, description, category, priority, status] = inputs;
  const taskId = actionElement.closest(".card-details").id;

  actionElement.addEventListener("click", () => {
    const body = {
      title: title.value,
      description: description.value,
      category: category.value,
      priority: priority.value,
      status: status.value,
    };
    updateTask(
      "https://alx-portfolio-fy5s.onrender.com/tasks",
      taskId,
      body
    ).then(() => {
      window.location.reload();
    });
  });
};

export const taskDetails = (cards, isExist = false) => {
  cards.forEach((card) => {
    card.addEventListener("click", (e) => {
      getOneTask(
        "https://alx-portfolio-fy5s.onrender.com/tasks",
        e.currentTarget.id
      ).then((task) => {
        getOneUser(
          "https://alx-portfolio-fy5s.onrender.com/users",
          task.creator_id
        ).then((user) => {
          document.body.classList.add("blur");
          createTaskDetails(taskDetailsContainer, task, user, isExist);
          closeTaskDetails(document.querySelector("#close"));
          handleDeleteTask(document.querySelector("#delete-btn"));
          const editBtn = document.querySelector("#edit-btn");
          const titleInput = document.querySelector("#title-input");
          const descriptionInput = document.querySelector("#description-input");
          const categoryInput = document.querySelector("#category-input");
          const priorityInput = document.querySelector("#priority-input");
          const statusInput = document.querySelector("#status-input");
          handleUpdateTask(
            editBtn,
            titleInput,
            descriptionInput,
            categoryInput,
            priorityInput,
            statusInput
          );
        });
      });
    });
  });
};
