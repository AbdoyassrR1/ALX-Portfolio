#!/usr/bin/python3
from models.engine.db_storage import PostgresqlDB


storage = PostgresqlDB()
storage.reload()
