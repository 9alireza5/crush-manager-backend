import mariadb
import datetime
from passlib.context import CryptContext  # For password hashing

# --- Password Hashing Setup (using Argon2 as preferred) ---
# schemes: argon2 is the primary hashing scheme. bcrypt is included as a fallback
# or for migrating older hashes if necessary.
# deprecated="auto": passlib will automatically upgrade hashes from deprecated schemes
# (like bcrypt if you later decide to only use argon2) upon successful verification.
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto"
)


class NotFoundError(Exception):
    # Custom exception for when a record is not found.
    pass


class UserExistsError(Exception):
    # Custom exception for when a user already exists during registration.
    pass


def get_db_connection():
    # IMPORTANT: For production, use a strong password and consider environment variables
    # or a config file for credentials instead of hardcoding.
    db_password = "awx2er0fRBTFD1uKQjEXze4Q"
    try:
        cnx = mariadb.connect(
            host="localhost",
            user="alirezza",  # Ensure this user exists and has the necessary permissions
            password=db_password,
            database="learningdb",  # Ensure this database exists
            port=3306  # Default MariaDB/MySQL port, change if necessary
        )
        return cnx
    except mariadb.Error as err:
        print(f"Database connection error: {err}")
        raise


def create_tables_if_not_exist(cursor):
    # Create crushes table (from previous version)
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS crushes
                   (
                       id
                       INT
                       AUTO_INCREMENT
                       PRIMARY
                       KEY,
                       first_name
                       VARCHAR
                   (
                       255
                   ),
                       last_name VARCHAR
                   (
                       255
                   ),
                       gender VARCHAR
                   (
                       10
                   ),
                       acquaintance_date DATE,
                       age INT,
                       phone_number VARCHAR
                   (
                       20
                   ),
                       instagram_id VARCHAR
                   (
                       50
                   ),
                       relationship_status VARCHAR
                   (
                       50
                   ),
                       interaction_level INT,
                       feelings_level INT,
                       future_plan VARCHAR
                   (
                       255
                   ),
                       notes TEXT
                       ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                   ''')
    # Create users table for authentication
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS users
                   (
                       id
                       INT
                       AUTO_INCREMENT
                       PRIMARY
                       KEY,
                       username
                       VARCHAR
                   (
                       80
                   ) UNIQUE NOT NULL,
                       password_hash VARCHAR
                   (
                       255
                   ) NOT NULL
                       ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                   ''')
    print("Checked/Created 'crushes' and 'users' tables.")


# --- Password Utilities ---
def hash_password(password):
    # Hashes a plain password using the configured pwd_context (Argon2).
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    # Verifies a plain password against a stored hash.
    return pwd_context.verify(plain_password, hashed_password)


# --- User Management Functions ---
def add_user(cursor, cnx, username, password):
    # Registers a new user with a hashed password.
    # Check if username already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        raise UserExistsError(f"Username '{username}' already exists.")

    hashed_pwd = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pwd))
        cnx.commit()
        return cursor.lastrowid
    except mariadb.Error as err:
        cnx.rollback()
        raise err


def get_user_by_username(cursor, username):
    # Retrieves a user by their username.
    cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        return None  # User not found

    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


# --- Validation Functions (for crushes data - kept from previous version) ---
def validate_text_field(value, field_name, max_length=None, allow_null=True):
    if value is None:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be null.")
    str_value = str(value).strip()
    if not str_value:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be empty.")
    if max_length and len(str_value) > max_length:
        raise ValueError(f"'{field_name}' exceeds maximum length of {max_length} characters.")
    return str_value


def validate_integer_field(value, field_name, min_val=None, max_val=None, allow_null=True):
    if value is None:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be null.")
    if isinstance(value, str):
        str_value = value.strip()
        if not str_value:
            if allow_null: return None
            raise ValueError(f"'{field_name}' cannot be empty.")
    else:
        str_value = str(value)
    try:
        int_value = int(str_value)
        if min_val is not None and int_value < min_val:
            raise ValueError(f"'{field_name}' must be at least {min_val}.")
        if max_val is not None and int_value > max_val:
            raise ValueError(f"'{field_name}' must be at most {max_val}.")
        return int_value
    except ValueError:
        raise ValueError(f"'{field_name}' is not a valid integer.")


def validate_gender_field(value, field_name, allow_null=True):
    if value is None:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be null.")
    str_value = str(value).strip().lower()
    if not str_value:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be empty.")
    if str_value not in ['male', 'female', 'other']:  # Added 'other' for inclusivity
        raise ValueError(f"'{field_name}' must be 'male', 'female', or 'other'.")
    return str_value


def validate_date_field(value, field_name, allow_null=True):
    if value is None:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be null.")
    str_value = str(value).strip()
    if not str_value:
        if allow_null: return None
        raise ValueError(f"'{field_name}' cannot be empty.")
    try:
        datetime.datetime.strptime(str_value, '%Y-%m-%d')
        return str_value
    except ValueError:
        raise ValueError(f"'{field_name}' has an invalid date format. Please use YYYY-MM-DD.")


# --- Crush Management Functions (kept from previous version, adapted for ? placeholder) ---
def list_all_crushes(cursor):
    query = "SELECT * FROM crushes"
    cursor.execute(query)
    rows = cursor.fetchall()
    if not rows: return []
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]


def get_crush_details(cursor, crush_id):
    query = "SELECT * FROM crushes WHERE id = ?"
    cursor.execute(query, (crush_id,))
    row = cursor.fetchone()
    if not row: raise NotFoundError(f"Crush with ID {crush_id} not found.")
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


def create_new_crush(cursor, cnx, crush_data):
    # Validate fields
    first_name = validate_text_field(crush_data.get('first_name'), 'first_name', max_length=255, allow_null=False)
    last_name = validate_text_field(crush_data.get('last_name'), 'last_name', max_length=255, allow_null=True)
    # ... (validate all other crush fields similarly) ...
    gender = validate_gender_field(crush_data.get('gender'), 'gender', allow_null=True)
    acquaintance_date = validate_date_field(crush_data.get('acquaintance_date'), 'acquaintance_date', allow_null=True)
    age = validate_integer_field(crush_data.get('age'), 'age', min_val=0, max_val=120, allow_null=True)
    phone_number = validate_text_field(crush_data.get('phone_number'), 'phone_number', max_length=20, allow_null=True)
    instagram_id = validate_text_field(crush_data.get('instagram_id'), 'instagram_id', max_length=50, allow_null=True)
    relationship_status = validate_text_field(crush_data.get('relationship_status'), 'relationship_status',
                                              max_length=50, allow_null=True)
    interaction_level = validate_integer_field(crush_data.get('interaction_level'), 'interaction_level', min_val=1,
                                               max_val=5, allow_null=True)
    feelings_level = validate_integer_field(crush_data.get('feelings_level'), 'feelings_level', min_val=1, max_val=5,
                                            allow_null=True)
    future_plan = validate_text_field(crush_data.get('future_plan'), 'future_plan', max_length=255, allow_null=True)
    notes = validate_text_field(crush_data.get('notes'), 'notes', allow_null=True)

    insert_sql_query = """
                       INSERT INTO crushes (first_name, last_name, gender, acquaintance_date, age, phone_number, \
                                            instagram_id,
                                            relationship_status, interaction_level, feelings_level,
                                            future_plan, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                       """
    record_to_insert = (
        first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
        relationship_status, interaction_level, feelings_level, future_plan, notes
    )
    try:
        cursor.execute(insert_sql_query, record_to_insert)
        cnx.commit()
        return cursor.lastrowid
    except mariadb.Error as err:
        cnx.rollback()
        raise err


def update_existing_crush(cursor, cnx, crush_id, update_data):
    get_crush_details(cursor, crush_id)  # Check existence
    set_clauses = []
    updated_values = []

    # Dynamically build the SET part of the query based on provided data
    # Example for one field:
    if 'first_name' in update_data:
        set_clauses.append("first_name = ?")
        updated_values.append(
            validate_text_field(update_data['first_name'], 'first_name', max_length=255, allow_null=False))
    # ... (add similar blocks for all updatable crush fields) ...
    if 'last_name' in update_data:
        set_clauses.append("last_name = ?")
        updated_values.append(
            validate_text_field(update_data['last_name'], 'last_name', max_length=255, allow_null=True))
    if 'gender' in update_data:
        set_clauses.append("gender = ?")
        updated_values.append(validate_gender_field(update_data['gender'], 'gender', allow_null=True))
    # ... (and so on for other fields)

    if not set_clauses:
        raise ValueError("No valid fields provided for update.")

    update_sql_query = f"UPDATE crushes SET {', '.join(set_clauses)} WHERE id = ?"
    updated_values.append(crush_id)
    try:
        cursor.execute(update_sql_query, tuple(updated_values))
        cnx.commit()
        return cursor.rowcount
    except mariadb.Error as err:
        cnx.rollback()
        raise err


def delete_existing_crush(cursor, cnx, crush_id):
    get_crush_details(cursor, crush_id)  # Check existence
    delete_sql_query = "DELETE FROM crushes WHERE id = ?"
    try:
        cursor.execute(delete_sql_query, (crush_id,))
        cnx.commit()
        if cursor.rowcount == 0:  # Should not happen if get_crush_details succeeded
            raise NotFoundError(f"Crush with ID {crush_id} found but deletion affected 0 rows.")
        return cursor.rowcount
    except mariadb.Error as err:
        cnx.rollback()
        raise err
