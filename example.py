from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Vulnerable to SQL Injection
@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    c.execute(query)
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({'id': user[0], 'username': user[1], 'email': user[2], 'password': user[3]})
    else:
        return jsonify({'error': 'User not found'}), 404

# Vulnerable to Cross-Site Scripting (XSS)
@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return f"<h1>User Profile</h1><p>Username: {user[1]}</p><p>Email: {user[2]}</p>"
    else:
        return jsonify({'error': 'User not found'}), 404

# Vulnerable to Insecure Direct Object References (IDOR)
@app.route('/update_email', methods=['POST'])
def update_email():
    user_id = request.form['user_id']
    new_email = request.form['email']
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Email updated'})

# Vulnerable to Improper Error Handling
@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        return jsonify({'message': 'User created', 'user_id': user_id})
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True)
