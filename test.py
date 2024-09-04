import psycopg2

try:
    conn = psycopg2.connect("postgresql://postgres:manjudubey@localhost/my_flask_db")
    print("Connection successful")
except Exception as e:
    print(f"Connection failed: {e}")
