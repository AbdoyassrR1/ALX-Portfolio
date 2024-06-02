export const createCardTask = (element, task, date) => {
  element.innerHTML += `
      <div class="task-card" id="${task.id}">
        <div class="intro">
          <h3 class="title" id="title">${task.title}</h3>
          <div class="task-date" id="task-date">
            <span>${date}</span>
            <i class="bi bi-calendar-date"></i>
          </div>
        </div>
        <p class="description" id="description">${task.description}</p>
        <div class="task-footer">
          <div class="task-priority" id="task-priority">
            <span>${task.priority}</span>
            ${task.priority == "High" ? `<i class="bi bi-star-fill"></i>` : ""}
            ${
              task.priority == "Medium" ? `<i class="bi bi-star-half"></i>` : ""
            }
            ${task.priority == "Low" ? `<i class="bi bi-star"></i>` : ""}
          </div>
          <div class="task-status" id="task-status">
            <span>${task.status}</span>
            ${task.status == "Todo" ? `<i class="bi bi-list-task"></i>` : ""}
            ${
              task.status == "In Progress"
                ? `<i class="bi bi-hourglass-split"></i>`
                : ""
            }
            ${
              task.status == "Done" ? `<i class="bi bi-check2-circle"></i>` : ""
            }
          </div>
          <div class="task-category" id="task-category">
            <span>${task.category}</span>
            ${task.category == "Study" ? `<i class="bi bi-book-fill"></i>` : ""}
            ${task.category == "Work" ? `<i class="bi bi-building"></i>` : ""}
            ${
              task.category == "Work Out"
                ? `<i class="bi bi-person-walking"></i>`
                : ""
            }
          </div>
        </div>
      </div>
    `;
};
