export const getUser = async (api, id) => {
  const user = await axios.get(`${api}/${id}`);
  return user.data;
};

export const updateUser = async (api, id, body) => {
  const user = await axios.patch(`${api}/${id}`, body, {
    headers: {
      "Content-Type": "application/json",
    },
  });
  return user.data;
};

export const deleteUser = async (api, id) => {
  const user = await axios.delete(`${api}/${id}`);
  return user.data;
};

export const getOneUser = async (api, id) => {
  const user = await axios.get(`${api}/${id}`);
  return user.data;
};
