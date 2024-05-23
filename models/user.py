#!/usr/bin/python3
"""
User class
"""
import models
from models.base_model import BaseModel, Base
from models.task import Task
from sqlalchemy import Column, String, Boolean, LargeBinary
from sqlalchemy.orm import relationship


class User(BaseModel, Base):
    __tablename__ = 'users'

    username = Column(String(50), nullable=False, unique=True)
    email = Column(String(50), nullable=False, unique=True)
    password = Column(LargeBinary, nullable=False)
    is_loggin= Column(Boolean, nullable=False, default=False)

    # tasks_created = relationship('Task', back_populates='creator',cascade="all, delete, save-update")
    tasks_created = relationship('Task', back_populates='creator')

    def __init__(self, *args, **kwargs):
        """initializes Place"""
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"{self.__class__.__name__}, username: {self.username}, id: {self.id}, email: {self.email}"

    def to_dict(self):
        time = "%a, %d %b %Y %I:%M:%S %p"
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password': str(self.password),
            'created_at': self.created_at.strftime(time),
            'updated_at': self.updated_at.strftime(time),
            "is_loggin": self.is_loggin
        }

    @property
    def created_tasks(self):
        """getter for list of tasks related to the user"""
        tasks_list = []
        all_tasks = models.storage.all(Task)
        for task in all_tasks.values():
            if task.state_id == self.id:
                tasks_list.append(task)
        return tasks_list
