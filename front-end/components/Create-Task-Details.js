export const createTaskDetails = (element, task, user, isExist) => {
  element.innerHTML = `
              <div class="card-details animate__animated animate__fadeIn" id="${
                task.id
              }">
              <button class="close" id="close">X</button>
              <label for="title-input">Title</label>
              <input type="text" id="title-input" value="${task.title}" ${
    isExist ? "" : "disabled"
  }>
              <label for="description-input">Description</label>
              <input type="text" id="description-input" value="${
                task.description
              }" ${isExist ? "" : "disabled"}>
              <label for="priority-input">Priority</label>
              <select name="priority" id="priority-input" ${
                isExist ? "" : "disabled"
              }>
                <option value="${task.priority}">${task.priority}</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <label for="status-input">Status</label>
              <select name="status" id="status-input" ${
                isExist ? "" : "disabled"
              }>
                <option value="${task.status}">${task.status}</option>
                <option value="todo">ToDo</option>
                <option value="in_progress">In Progress</option>
                <option value="done">Done</option>
              </select>
              <label for="category-input">Category</label>
              <select name="category" id="category-input" ${
                isExist ? "" : "disabled"
              }>
                <option value="${task.category}">${task.category}</option>
                <option value="study">Study</option>
                <option value="work">Work</option>
                <option value="workout">Work Out</option>
              </select>
              <label for="user_name">User Name</label>
              <input type="text" id="user_name" value="${
                user.username
              }" disabled>
              <label for="date-input">Date</label>
              <input type="text" id="date-input" value="${
                task.updated_at
              }" disabled>
              ${
                isExist
                  ? `<div class="task-details-control">
              <button class="delete" id="delete-btn">Delete</button>
              <button class="edit" id="edit-btn">Edit</button>
              </div>`
                  : ""
              }
              </div>
              `;
};
