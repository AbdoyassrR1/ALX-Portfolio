export const validationForm = (body, isSignIn, ...elements) => {
  const [userNameInput, emailInput, passwordInput, userNameEmailInput] =
    elements;
  const { username, email, password } = body;
  const errors = [];
  if (username !== undefined) {
    if (username === "") {
      errors.push("Username is required");
      userNameInput?.classList.add("animate__shakeX");
    }
    if (username.length < 8) {
      errors.push("Username must be at least 8 characters");
      userNameInput?.classList.add("animate__shakeX");
    }
  }

  if (isSignIn) {
    if (email === "") {
      errors.push("Username or email is required");
      userNameEmailInput?.classList.add("animate__shakeX");
    }
  }

  if (!isSignIn) {
    if (email !== undefined) {
      if (email === "") {
        errors.push("Email is required");
        emailInput?.classList.add("animate__shakeX");
      } else if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@gmail\.com$/.test(email)) {
        errors.push("Email is not valid");
        emailInput?.classList.add("animate__shakeX");
      }
    }
  }
  if (password !== undefined) {
    if (password === "") {
      errors.push("Password is required");
      passwordInput?.classList.add("animate__shakeX");
    } else if (password.length < 8) {
      errors.push("Password must be at least 8 characters");
      passwordInput?.classList.add("animate__shakeX");
    }
  }

  return errors;
};
