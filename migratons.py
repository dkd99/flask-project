from flask_migrate import Migrate
from app import app  # Import your app and db objects
from db import db
migrate = Migrate(app, db)
