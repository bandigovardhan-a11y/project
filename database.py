
import os
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password=os.environ["Govardhan@2003"],
        database="skill_swap",
        port=3306
    )
