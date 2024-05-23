#!/usr/bin/python3
"""
Task class
"""

from models.base_model import BaseModel, Base
import enum
from sqlalchemy import Column, String, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship


class TaskStatus(enum.Enum):
    TODO = 'Todo'
    IN_PROGRESS = 'In Progress'
    DONE = 'Done'


class TaskPriority(enum.Enum):
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'


class TaskCategory(enum.Enum):
    WORK = 'Work'
    STUDY = 'Study'
    WORKOUT = 'Workout'


class Task(BaseModel, Base):
    __tablename__ = 'tasks'

    title = Column(String(50), nullable=False)
    description = Column(Text)
    status = Column(Enum(TaskStatus), nullable=False, default=TaskStatus.TODO)
    priority = Column(Enum(TaskPriority), nullable=False, default=TaskPriority.HIGH)
    category = Column(Enum(TaskCategory), nullable=False, default=TaskCategory.WORK)
    # creator_id = Column(String(60), ForeignKey('users.id', ondelete="CASCADE", onupdate="CASCADE"))
    creator_id = Column(String(60), ForeignKey('users.id'))

    creator = relationship('User', back_populates='tasks_created')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return f"Class: {self.__class__.__name__}, title: {self.title}, id: {self.id}, creator_id: {self.creator_id}"

    def to_dict(self):
        """Convert instance to dictionary"""
        time = "%a, %d %b %Y %I:%M:%S %p"
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status.value,  # Convert enum to string
            'priority': self.priority.value,  # Convert enum to string
            'category': self.category.value,  # Convert enum to string
            'creator_id': self.creator_id,
            'created_at': self.created_at.strftime(time),
            'updated_at': self.updated_at.strftime(time)
        }
