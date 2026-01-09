import sqlite3
import json
import os
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path='data/data.db'):
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_db()

    def _ensure_db_dir(self):
        dirname = os.path.dirname(self.db_path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # 基础配置和通知配置设置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # 同步任务表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sync_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_name TEXT,
                sync_mode TEXT,
                source_storage TEXT,
                target_storages TEXT, -- JSON 数组
                sync_dirs TEXT,
                exclude_dirs TEXT,
                sync_del_action TEXT,
                cron TEXT,
                random_delay INTEGER DEFAULT 0,
                regex_patterns TEXT,
                paths TEXT -- 文件同步路径 JSON 数组
            )
        ''')
        
        # 用户表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT
            )
        ''')

        # 通知配置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                type TEXT, -- e.g., 'bark'
                config TEXT, -- JSON 字符串存储具体配置
                enabled INTEGER DEFAULT 1
            )
        ''')

        conn.commit()
        conn.close()

    def get_setting(self, key, default=None):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        conn.close()
        return row['value'] if row else default

    def set_setting(self, key, value):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()

    def get_all_settings(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM settings')
        rows = cursor.fetchall()
        conn.close()
        return {row['key']: row['value'] for row in rows}

    def get_tasks(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sync_tasks')
        rows = cursor.fetchall()
        tasks = []
        for row in rows:
            task = dict(row)
            # 解析 JSON 字段
            if task['target_storages']:
                try:
                    task['targetStorages'] = json.loads(task['target_storages'])
                except:
                    task['targetStorages'] = []
            else:
                 task['targetStorages'] = []

            if task['paths']:
                try:
                    task['paths'] = json.loads(task['paths'])
                except:
                    task['paths'] = []
            else:
                task['paths'] = []
            
            # 将蛇形命名数据库字段映射为驼峰命名 API 字段（如果需要），或在 API 层处理
            # 为简单起见，我这里直接返回带驼峰命名键的字典以符合前端预期
            task_dict = {
                'id': task['id'],
                'taskName': task['task_name'],
                'syncMode': task['sync_mode'],
                'sourceStorage': task['source_storage'],
                'targetStorages': task['targetStorages'],
                'syncDirs': task['sync_dirs'],
                'excludeDirs': task['exclude_dirs'],
                'syncDelAction': task['sync_del_action'],
                'cron': task['cron'],
                'randomDelay': task['random_delay'],
                'regexPatterns': task['regex_patterns'],
                'paths': task['paths']
            }
            tasks.append(task_dict)
        conn.close()
        return tasks

    def get_task(self, task_id):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sync_tasks WHERE id = ?', (task_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        
        task = dict(row)
        # 解析 JSON 并像 get_tasks 一样映射键
        if task['target_storages']:
             try: task['targetStorages'] = json.loads(task['target_storages'])
             except: task['targetStorages'] = []
        else: task['targetStorages'] = []

        if task['paths']:
             try: task['paths'] = json.loads(task['paths'])
             except: task['paths'] = []
        else: task['paths'] = []

        return {
                'id': task['id'],
                'taskName': task['task_name'],
                'syncMode': task['sync_mode'],
                'sourceStorage': task['source_storage'],
                'targetStorages': task['targetStorages'],
                'syncDirs': task['sync_dirs'],
                'excludeDirs': task['exclude_dirs'],
                'syncDelAction': task['sync_del_action'],
                'cron': task['cron'],
                'randomDelay': task['random_delay'],
                'regexPatterns': task['regex_patterns'],
                'paths': task['paths']
            }

    def add_task(self, task_data):
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # 检查是否提供了 ID
        task_id = task_data.get('id')
        if task_id is not None:
             cursor.execute('''
                INSERT INTO sync_tasks (
                    id, task_name, sync_mode, source_storage, target_storages, 
                    sync_dirs, exclude_dirs, sync_del_action, cron, 
                    random_delay, regex_patterns, paths
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task_id,
                task_data.get('taskName'),
                task_data.get('syncMode'),
                task_data.get('sourceStorage'),
                json.dumps(task_data.get('targetStorages', [])),
                task_data.get('syncDirs'),
                task_data.get('excludeDirs'),
                task_data.get('syncDelAction'),
                task_data.get('cron'),
                task_data.get('randomDelay', 0),
                task_data.get('regexPatterns'),
                json.dumps(task_data.get('paths', []))
            ))
        else:
             cursor.execute('''
                INSERT INTO sync_tasks (
                    task_name, sync_mode, source_storage, target_storages, 
                    sync_dirs, exclude_dirs, sync_del_action, cron, 
                    random_delay, regex_patterns, paths
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task_data.get('taskName'),
                task_data.get('syncMode'),
                task_data.get('sourceStorage'),
                json.dumps(task_data.get('targetStorages', [])),
                task_data.get('syncDirs'),
                task_data.get('excludeDirs'),
                task_data.get('syncDelAction'),
                task_data.get('cron'),
                task_data.get('randomDelay', 0),
                task_data.get('regexPatterns'),
                json.dumps(task_data.get('paths', []))
            ))
            
        new_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return new_id

    def update_task(self, task_data):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sync_tasks SET
                task_name = ?, sync_mode = ?, source_storage = ?, target_storages = ?,
                sync_dirs = ?, exclude_dirs = ?, sync_del_action = ?, cron = ?,
                random_delay = ?, regex_patterns = ?, paths = ?
            WHERE id = ?
        ''', (
            task_data.get('taskName'),
            task_data.get('syncMode'),
            task_data.get('sourceStorage'),
            json.dumps(task_data.get('targetStorages', [])),
            task_data.get('syncDirs'),
            task_data.get('excludeDirs'),
            task_data.get('syncDelAction'),
            task_data.get('cron'),
            task_data.get('randomDelay', 0),
            task_data.get('regexPatterns'),
            json.dumps(task_data.get('paths', [])),
            task_data.get('id')
        ))
        conn.commit()
        conn.close()
        return True

    def delete_task(self, task_id):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sync_tasks WHERE id = ?', (task_id,))
        conn.commit()
        conn.close()
        return True
        
    def get_users(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        rows = cursor.fetchall()
        conn.close()
        return [{'username': row['username'], 'password': row['password']} for row in rows]
        
    def add_user(self, username, password):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()

    def update_user_password(self, username, password):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (password, username))
        conn.commit()
        conn.close()

    # 通知相关
    def get_notifications(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM notification_configs')
        rows = cursor.fetchall()
        conn.close()
        notifications = []
        for row in rows:
            notif = dict(row)
            try:
                notif['config'] = json.loads(notif['config'])
            except:
                notif['config'] = {}
            notifications.append(notif)
        return notifications

    def add_notification(self, name, type, config, enabled=1):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO notification_configs (name, type, config, enabled) VALUES (?, ?, ?, ?)',
            (name, type, json.dumps(config), enabled)
        )
        new_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return new_id

    def update_notification(self, id, name, type, config, enabled):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE notification_configs SET name = ?, type = ?, config = ?, enabled = ? WHERE id = ?',
            (name, type, json.dumps(config), enabled, id)
        )
        conn.commit()
        conn.close()
        return True

    def delete_notification(self, id):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM notification_configs WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        return True

    def toggle_notification(self, id, enabled):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('UPDATE notification_configs SET enabled = ? WHERE id = ?', (enabled, id))
        conn.commit()
        conn.close()
        return True

