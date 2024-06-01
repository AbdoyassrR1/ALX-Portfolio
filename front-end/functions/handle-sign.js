export const handleSignPost = async (e, api, body) => {
  e.preventDefault();
  try {
    const signInUpRes = await axios.post(`${api}`, body, {
      headers: {
        "Content-Type": "application/json",
      },
    });
    console.log(signInUpRes.data);
    window.localStorage.setItem("user_id", signInUpRes.data.id);
    window.localStorage.setItem("isLoggedIn", signInUpRes.data.is_loggin);
    return signInUpRes;
  } catch (error) {
    return error;
  }
};

export const handleSignGet = async (e, api, userId) => {
  e.preventDefault();
  try {
    await axios.get(`${api}/${userId}`, {
      headers: {
        "Content-Type": "application/json",
      },
    });
    localStorage.removeItem("user_id");
    localStorage.removeItem("isLoggedIn");
  } catch (error) {
    return error;
  }
};
