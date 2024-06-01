export const noTasks = (element) => {
  element.innerHTML = `
        <div class="no-tasks animate__animated animate__wobble">
            <i class="bi bi-emoji-frown-fill"></i>
            <h3>No tasks found</h3>
        </div>
    `;
};
