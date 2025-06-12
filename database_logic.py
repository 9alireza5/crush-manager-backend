import mariadb
import datetime
import secrets
from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto"
)

class NotFoundError(Exception):
    pass

class UserExistsError(Exception):
    pass

class UnauthorizedError(Exception):
    pass

def get_db_connection():
    db_password = "awx2er0fRBTFD1uKQjEXze4Q"
    try:
        cnx = mariadb.connect(
            host="localhost",
            user="alirezza",
            password=db_password,
            database="learningdb",
            port=3306
        )
        return cnx
    except mariadb.Error as err:
        print(f"Database connection error: {err}")
        raise

def create_tables_if_not_exist(cursor):
    # Role-Based Access Control (RBAC) Change: Added 'role' column to users table.
    # AI Feature Change: Added 'ai_summary' column to store AI's impression of the user.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            ai_summary TEXT NULLABLE,
            reset_token VARCHAR(100) UNIQUE NULLABLE,
            reset_token_expires_at DATETIME NULLABLE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS crushes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            first_name VARCHAR(255),
            last_name VARCHAR(255),
            gender VARCHAR(50),
            acquaintance_date DATE,
            age INT,
            phone_number VARCHAR(20),
            instagram_id VARCHAR(50),
            relationship_status VARCHAR(100),
            interaction_level INT,
            feelings_level INT,
            future_plan VARCHAR(255),
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    ''')
    # AI Feature Change: Added 'ai_chat_history' table to remember conversations.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_chat_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            prompt_text TEXT NOT NULL,
            response_text TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    ''')
    print("Checked/Created 'users', 'crushes', and 'ai_chat_history' tables.")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def add_user(cursor, cnx, username, email, password):
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone():
        raise UserExistsError("Username or email already exists.")
    hashed_pwd = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                       (username, email, hashed_pwd))
        cnx.commit()
        return cursor.lastrowid
    except mariadb.Error as err:
        cnx.rollback()
        raise err

def get_user_by_username(cursor, username):
    # RBAC Change: Fetch 'role' and 'ai_summary' along with other user data.
    cursor.execute("SELECT id, username, email, password_hash, role, ai_summary FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row: return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))

def get_user_by_id(cursor, user_id):
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row: return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))

def get_user_by_email(cursor, email):
    cursor.execute("SELECT id, username, email FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    if not row: return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))

def update_user_profile(cursor, cnx, user_id, email=None, new_password=None):
    set_clauses = []
    update_values = []
    if email:
        cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id))
        if cursor.fetchone():
            raise UserExistsError(f"Email '{email}' is already registered by another user.")
        set_clauses.append("email = ?")
        update_values.append(email)
    if new_password:
        set_clauses.append("password_hash = ?")
        update_values.append(hash_password(new_password))
    if not set_clauses:
        raise ValueError("No information provided for update (email or new_password).")
    update_values.append(user_id)
    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
    try:
        cursor.execute(query, tuple(update_values))
        cnx.commit()
        return cursor.rowcount > 0
    except mariadb.Error as err:
        cnx.rollback()
        raise err

def set_password_reset_token_for_user(cursor, cnx, user_id):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    try:
        cursor.execute("UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?",
                       (token, expires_at, user_id))
        cnx.commit()
        return token
    except mariadb.Error as err:
        cnx.rollback()
        raise err

def get_user_by_reset_token(cursor, token):
    cursor.execute("SELECT id, username, email, reset_token_expires_at FROM users WHERE reset_token = ?", (token,))
    row = cursor.fetchone()
    if not row: return None
    columns = [desc[0] for desc in cursor.description]
    user = dict(zip(columns, row))
    if user['reset_token_expires_at'] < datetime.datetime.utcnow():
        return None
    return user

def reset_user_password(cursor, cnx, user_id, new_password):
    hashed_pwd = hash_password(new_password)
    try:
        cursor.execute("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?",
                       (hashed_pwd, user_id))
        cnx.commit()
        return cursor.rowcount > 0
    except mariadb.Error as err:
        cnx.rollback()
        raise err

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
    else: str_value = str(value)
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
    allowed_genders = ['male', 'female', 'other', 'non-binary', 'prefer not to say']
    if str_value not in allowed_genders:
        raise ValueError(f"'{field_name}' must be one of {', '.join(allowed_genders)}.")
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
        return datetime.datetime.strptime(str_value, '%Y-%m-%d').date()
    except ValueError:
        raise ValueError(f"'{field_name}' has an invalid date format. Please use YYYY-MM-DD.")

def get_crushes_summary_for_ai(cursor, user_id):
    query = "SELECT first_name, notes, relationship_status, interaction_level, feelings_level FROM crushes WHERE user_id = ?"
    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    if not rows:
        return "User has no recorded crush information to discuss."
    summary_parts = []
    for row_data in rows:
        columns = [desc[0] for desc in cursor.description]
        crush_info = dict(zip(columns, row_data))
        summary_parts.append(
            f"- Crush: {crush_info.get('first_name', 'N/A')}. "
            f"Status: {crush_info.get('relationship_status', 'N/A')}. "
            f"Interaction: {crush_info.get('interaction_level', 'N/A')}/5. "
            f"User's Feelings: {crush_info.get('feelings_level', 'N/A')}/5. "
            f"Notes: '{crush_info.get('notes', 'No specific notes.')}'"
        )
    return "\n".join(summary_parts)

def list_crushes(cursor, user_id=None, page=1, limit=10, sort_by='id', sort_order='asc', filters=None):
    query_params = []
    base_query = "SELECT * FROM crushes"
    where_clauses = []
    if user_id:
        where_clauses.append("user_id = ?")
        query_params.append(user_id)
    if filters:
        if filters.get('gender'):
            where_clauses.append("gender = ?")
            query_params.append(filters['gender'])
        if filters.get('name_contains'):
            where_clauses.append("(first_name LIKE ? OR last_name LIKE ?)")
            query_params.append(f"%{filters['name_contains']}%")
            query_params.append(f"%{filters['name_contains']}%")
        if filters.get('min_age') is not None:
            where_clauses.append("age >= ?")
            query_params.append(filters['min_age'])
        if filters.get('max_age') is not None:
            where_clauses.append("age <= ?")
            query_params.append(filters['max_age'])
        if filters.get('acquaintance_date_after'):
            where_clauses.append("acquaintance_date >= ?")
            query_params.append(filters['acquaintance_date_after'])
        if filters.get('acquaintance_date_before'):
            where_clauses.append("acquaintance_date <= ?")
            query_params.append(filters['acquaintance_date_before'])
        if filters.get('interaction_level') is not None:
            where_clauses.append("interaction_level = ?")
            query_params.append(filters['interaction_level'])
        if filters.get('feelings_level') is not None:
            where_clauses.append("feelings_level = ?")
            query_params.append(filters['feelings_level'])
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)
    allowed_sort_columns = ['id', 'first_name', 'last_name', 'acquaintance_date', 'age', 'relationship_status', 'interaction_level', 'feelings_level', 'gender']
    if sort_by not in allowed_sort_columns: sort_by = 'id'
    sort_order_sql = "ASC" if sort_order.lower() == 'asc' else "DESC"
    base_query += f" ORDER BY {sort_by} {sort_order_sql}"
    offset = (page - 1) * limit
    base_query += " LIMIT ? OFFSET ?"
    query_params.extend([limit, offset])
    cursor.execute(base_query, tuple(query_params))
    rows = cursor.fetchall()
    count_query_base = "SELECT COUNT(*) FROM crushes"
    count_params_list = query_params[:-2]
    if where_clauses:
        count_query = count_query_base + " WHERE " + " AND ".join(where_clauses)
    else: count_query = count_query_base
    cursor.execute(count_query, tuple(count_params_list))
    total_count = cursor.fetchone()[0]
    if not rows: return [], total_count
    columns = [desc[0] for desc in cursor.description]
    results = [dict(zip(columns, row)) for row in rows]
    return results, total_count

def get_crush_details(cursor, crush_id):
    query = "SELECT * FROM crushes WHERE id = ?"
    cursor.execute(query, (crush_id,))
    row = cursor.fetchone()
    if not row:
        raise NotFoundError(f"Crush with ID {crush_id} not found.")
    columns = [desc[0] for desc in cursor.description]
    crush_dict = dict(zip(columns, row))
    if isinstance(crush_dict.get('acquaintance_date'), datetime.date):
        crush_dict['acquaintance_date'] = crush_dict['acquaintance_date'].isoformat()
    return crush_dict

def create_new_crush_for_user(cursor, cnx, crush_data, user_id):
    first_name = validate_text_field(crush_data.get('first_name'), 'first_name', max_length=255, allow_null=False)
    last_name = validate_text_field(crush_data.get('last_name'), 'last_name', max_length=255, allow_null=True)
    gender = validate_gender_field(crush_data.get('gender'), 'gender', allow_null=True)
    acquaintance_date_obj = validate_date_field(crush_data.get('acquaintance_date'), 'acquaintance_date', allow_null=True)
    acquaintance_date_str = acquaintance_date_obj.isoformat() if acquaintance_date_obj else None
    age = validate_integer_field(crush_data.get('age'), 'age', min_val=0, max_val=120, allow_null=True)
    phone_number = validate_text_field(crush_data.get('phone_number'), 'phone_number', max_length=20, allow_null=True)
    instagram_id = validate_text_field(crush_data.get('instagram_id'), 'instagram_id', max_length=50, allow_null=True)
    relationship_status = validate_text_field(crush_data.get('relationship_status'), 'relationship_status', max_length=100, allow_null=True)
    interaction_level = validate_integer_field(crush_data.get('interaction_level'), 'interaction_level', min_val=1, max_val=5, allow_null=True)
    feelings_level = validate_integer_field(crush_data.get('feelings_level'), 'feelings_level', min_val=1, max_val=5, allow_null=True)
    future_plan = validate_text_field(crush_data.get('future_plan'), 'future_plan', max_length=255, allow_null=True)
    notes = validate_text_field(crush_data.get('notes'), 'notes', allow_null=True)

    insert_sql_query = """
        INSERT INTO crushes (user_id, first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
                             relationship_status, interaction_level, feelings_level,
                             future_plan, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
        """
    record_to_insert = (
        user_id, first_name, last_name, gender, acquaintance_date_str, age, phone_number, instagram_id,
        relationship_status, interaction_level, feelings_level, future_plan, notes
    )
    try:
        cursor.execute(insert_sql_query, record_to_insert)
        cnx.commit()
        return cursor.lastrowid
    except mariadb.Error as err:
        cnx.rollback()
        raise err

def update_existing_crush_for_user(cursor, cnx, crush_id, user_id, update_data):
    set_clauses = []
    updated_values = []
    crush_fields_validators = {
        'first_name': lambda val: validate_text_field(val, 'first_name', max_length=255, allow_null=False),
        'last_name': lambda val: validate_text_field(val, 'last_name', max_length=255, allow_null=True),
        'gender': lambda val: validate_gender_field(val, 'gender', allow_null=True),
        'acquaintance_date': lambda val: validate_date_field(val, 'acquaintance_date', allow_null=True),
        'age': lambda val: validate_integer_field(val, 'age', min_val=0, max_val=120, allow_null=True),
        'phone_number': lambda val: validate_text_field(val, 'phone_number', max_length=20, allow_null=True),
        'instagram_id': lambda val: validate_text_field(val, 'instagram_id', max_length=50, allow_null=True),
        'relationship_status': lambda val: validate_text_field(val, 'relationship_status', max_length=100, allow_null=True),
        'interaction_level': lambda val: validate_integer_field(val, 'interaction_level', min_val=1, max_val=5, allow_null=True),
        'feelings_level': lambda val: validate_integer_field(val, 'feelings_level', min_val=1, max_val=5, allow_null=True),
        'future_plan': lambda val: validate_text_field(val, 'future_plan', max_length=255, allow_null=True),
        'notes': lambda val: validate_text_field(val, 'notes', allow_null=True)
    }
    for field, validator_func in crush_fields_validators.items():
        if field in update_data:
            validated_value = validator_func(update_data[field])
            if isinstance(validated_value, datetime.date):
                updated_values.append(validated_value.isoformat())
            else:
                updated_values.append(validated_value)
            set_clauses.append(f"{field} = ?")
    if not set_clauses:
        raise ValueError("No valid fields provided for update.")
    update_sql_query = f"UPDATE crushes SET {', '.join(set_clauses)} WHERE id = ? AND user_id = ?"
    updated_values.extend([crush_id, user_id])
    try:
        cursor.execute(update_sql_query, tuple(updated_values))
        cnx.commit()
        if cursor.rowcount == 0:
            cursor.execute("SELECT id FROM crushes WHERE id = ? AND user_id = ?", (crush_id, user_id))
            if not cursor.fetchone():
                raise NotFoundError(f"Crush with ID {crush_id} not found for this user.")
            raise UnauthorizedError(f"No changes made to crush ID {crush_id}. Data might be identical, or not authorized.")
        return cursor.rowcount
    except mariadb.Error as err:
        cnx.rollback()
        raise err

def delete_existing_crush_for_user(cursor, cnx, crush_id, user_id):
    delete_sql_query = "DELETE FROM crushes WHERE id = ? AND user_id = ?"
    try:
        cursor.execute(delete_sql_query, (crush_id, user_id))
        cnx.commit()
        if cursor.rowcount == 0:
            raise NotFoundError(f"Crush with ID {crush_id} not found or not accessible by this user for deletion.")
        return cursor.rowcount
    except mariadb.Error as err:
        cnx.rollback()
        raise err

# AI Feature: New functions to handle chat history database interactions.
def add_chat_history(cursor, cnx, user_id, prompt_text, response_text):
    query = "INSERT INTO ai_chat_history (user_id, prompt_text, response_text) VALUES (?, ?, ?)"
    try:
        cursor.execute(query, (user_id, prompt_text, response_text))
        cnx.commit()
    except mariadb.Error as err:
        cnx.rollback()
        print(f"Error saving chat history: {err}") # Log this error appropriately

def get_chat_history(cursor, user_id, limit=5):
    query = "SELECT prompt_text, response_text FROM ai_chat_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
    cursor.execute(query, (user_id, limit))
    rows = cursor.fetchall()
    history = []
    if rows:
        # Gemini multi-turn chat expects a specific format, we build it here.
        # Format is typically [{'role':'user', 'parts': [...]}, {'role':'model', 'parts': [...]}, ...]
        for prompt, response in reversed(rows): # reverse to get chronological order
            history.append({'role': 'user', 'parts': [prompt]})
            history.append({'role': 'model', 'parts': [response]})
    return history

# AI Feature: New function to update the AI's summary of the user.
def update_ai_summary_for_user(cursor, cnx, user_id, summary):
    query = "UPDATE users SET ai_summary = ? WHERE id = ?"
    try:
        cursor.execute(query, (summary, user_id))
        cnx.commit()
    except mariadb.Error as err:
        cnx.rollback()
        print(f"Error updating AI summary: {err}") # Log this error appropriately

# RBAC Feature: New function for admins to update a user's role.
def update_user_role(cursor, cnx, user_id, new_role):
    allowed_roles = ['user', 'advisor', 'admin']
    if new_role not in allowed_roles:
        raise ValueError("Invalid role specified.")
    try:
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        cnx.commit()
        if cursor.rowcount == 0:
            raise NotFoundError(f"User with ID {user_id} not found.")
        return True
    except mariadb.Error as err:
        cnx.rollback()
        raise err

# RBAC Feature: New function for admins to list all users.
def list_all_users(cursor):
    cursor.execute("SELECT id, username, email, role FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    if not rows: return []
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]