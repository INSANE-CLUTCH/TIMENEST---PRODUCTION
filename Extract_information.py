# ham get_user tra ve 1 dict voi cac key duoc define san (line 56). Co cac che do extract theo month hoac week
# Data va label duoc dung cho lam vi du cho model o trong data.py, co the them hoac sua cho predict tot hon.
# pip install ...
from data import categories
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from pymongo import MongoClient
from datetime import datetime, timedelta
import calendar
import os
from dotenv import load_dotenv
load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
client = MongoClient(MONGODB_URL)
model = SentenceTransformer('all-MiniLM-L6-v2')

def categorize_task(task):
    category_embeddings = {}
    for category, examples in categories.items():
        category_embeddings[category] = model.encode(category + ": " + ", ".join(examples))

    task_embedding = model.encode(task)
    similarities = {}
    for category, category_embedding in category_embeddings.items():
        similarity = cosine_similarity([task_embedding], [category_embedding])[0][0]
        similarities[category] = similarity
    
    best_category = max(similarities, key=similarities.get)
    return best_category

def get_user_information(client, mode: str = "week", user_id: str = ''):
    db = client.Timenest
    tasks_collection = db.tasks
    now = datetime.now()
    start_of_time = now 
    end_of_time = now

    if mode ==  'week': 
        start_of_time = now - timedelta(days=now.isoweekday() - 1)
        end_of_time = start_of_time + timedelta(days=6)
    if mode == 'month': 
        start_of_time = now.replace(day=1)
        last_day_of_month = calendar.monthrange(now.year, now.month)[1]
        end_of_time = now.replace(day=last_day_of_month)

    tasks = tasks_collection.find({
        "userID": user_id,
        "startTime": {
            "$gte": start_of_time.isoformat() + 'Z', 
            "$lte": end_of_time.isoformat() + 'Z'
        }
    })

    users_task_analysist = [{
        'user_id': 1,
        'hours': 0, #Tong so gio lam viec trong tuan/thang
        'tasks': [], # Before mapping, day is the earliest start day of the task.
        'categories': [] #After mapping, remove day.
    }]

    for task in tasks: 
        user_id = task['userID']
        task_name = task['taskName']
        start_time = task['startTime']
        end_time = task['endTime']
        start_time = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        end_time = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        spend_time = end_time - start_time 
        task_hours = spend_time.total_seconds()/3600

        user_found = False
        for user_task in users_task_analysist:
            if user_task['user_id'] == user_id:
                user_task['hours'] += task_hours  
                exist = 0
                for subtask in user_task['tasks']:
                    if subtask[0] ==  task_name: 
                        subtask[1] += task_hours
                        exist = 1
                if exist == 0: 
                    user_task['tasks'].append([task_name, task_hours, str(start_time)])
                user_found = True
                break
        
        # If the user is not found in the list, create a new user entry
        if not user_found:
            users_task_analysist.append({
                'user_id': user_id,
                'hours': task_hours,
                'tasks': [([task_name, task_hours, str(start_time)])],
                'categories': []
            })

    users_task_analysist = users_task_analysist[1:]

    for user in users_task_analysist:
        for task in user['tasks']: 
            map_category = categorize_task(task[0])  
            existed = 0 
            for cate in user['categories']: 
                if map_category == cate[0]: 
                    cate[1] += task[1]
                    existed = 1 
            if existed == 0: 
                user['categories'].append([map_category, task[1]])

    return users_task_analysist
