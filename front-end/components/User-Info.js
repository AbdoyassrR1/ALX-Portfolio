export const setUserInfo = (element, user) => {
  element.innerHTML += `
      <span>
          <i class="bi bi-person-circle"></i>
      </span>
      <h1 class="user-name" id="user-name">${user.username}</h1>
      <p p class="user-email" id="user-email">${user.email}</p>
      <div class="user-control" id="user-control">
          <button class="edit-info" id="edit-info">Edit Info</button>
          <button class="delete-user" id="delete-user">Delete My Account</button>
      </div>
      `;
};

export const editForm = (element) => {
  element.innerHTML = `
      <div class="edit-form" id="edit-form">
        <label for="username">Username</label>
        <input type="text" name="username" id="username">
        <label for="email">Email</label>
        <input type="text" name="email" id="email">
        <div class="edit-control" id="edit-control">
            <button type="button" class="cancel" id="cancel">Cancel</button>
            <button type="button" class="save" id="save">Save</button>
        </div>
      </div>
      `;
};

export const verifyDeleteAccount = (element) => {
  element.innerHTML = `
      <div class="delete-form" id="delete-form">
        <p>Are you sure you want to delete your account?</p>
        <div class="delete-control" id="delete-control">
            <button type="button" class="cancel" id="cancel">Cancel</button>
            <button type="button" class="delete" id="delete">Delete</button>
        </div>
      </div>
      `;
};
