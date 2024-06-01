export const getAllTasks = async (api, params) => {
  if (!params) {
    const tasks = await axios.get(`${api}`);
    return tasks.data;
  }
  const { category, priority, status, search } = params;
  const tasks = await axios.get(
    `${api}?category=${category}&priority=${priority}&status=${status}&search=${search}`,
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  return tasks.data;
};

export const getOneTask = async (api, id) => {
  const task = await axios.get(`${api}/${id}`);
  return task.data;
};

export const getTasksUser = async (api, id, params) => {
  if (!params) {
    const tasks = await axios.get(`${api}/${id}/tasks`);
    return tasks.data;
  }
  const { category, priority, status, search } = params;
  const tasks = await axios.get(
    `${api}/${id}/tasks?category=${category}&priority=${priority}&status=${status}&search=${search}`,
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  return tasks.data;
};

export const createTask = async (api, body) => {
  const task = await axios.post(`${api}`, body, {
    headers: {
      "Content-Type": "application/json",
    },
  });
  return task.data;
};

export const updateTask = async (api, id, body) => {
  const task = await axios.patch(`${api}/${id}`, body, {
    headers: {
      "Content-Type": "application/json",
    },
  });
  return task.data;
};

export const deleteTask = async (api, id) => {
  const task = await axios.delete(`${api}/${id}`);
  return task.data;
};
