import os
import sqlite3
from bcrypt import checkpw

# Create the db directory if it doesn't exist
db_directory = 'db/'
if not os.path.exists(db_directory):
    os.makedirs(db_directory)


# Path to your SQLite database
DB_PATH = os.path.join(db_directory, 'chat.db')

# Connect to the SQLite database
conn = sqlite3.connect(DB_PATH)


def create_db():
    # Create a cursor object using the connection
    cursor = conn.cursor()

    # SQL statement for creating the users table
    create_table_sql = '''    
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    '''
    # Execute the SQL statement to create the table
    cursor.execute(create_table_sql)

    # Commit the changes and close the connection
    conn.commit()


def register_user(conn, email, password_hash):
    """Register a new user with email, password hash, and public key."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError as e:
        print("Failed to register user:", e)
        return False

def authenticate_user(conn, email, password_attempt):
    """Authenticate a user based on email and attempted password."""
    cursor = conn.cursor()
    
    # Get the hashed password from the database for the given email
    cursor.execute(
        "SELECT password_hash FROM users WHERE email = ?",
        (email,)
    )
    user_record = cursor.fetchone()
    
    if user_record:
        # Extract the password hash from the first column of the user record
        stored_hash = user_record[0]
        
        # Verify the password attempt against the stored hash
        if checkpw(password_attempt.encode(), stored_hash):
            print("Authentication successful.")
            return True
        else:
            print("Authentication failed: Incorrect password.")
            return False
    else:
        print("Authentication failed: No user found with that email.")
        return False


if __name__ == '__main__':
    create_db()