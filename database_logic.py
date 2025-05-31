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
                       email VARCHAR
                   (
                       120
                   ) UNIQUE NOT NULL,
                       password_hash VARCHAR
                   (
                       255
                   ) NOT NULL,
                       reset_token VARCHAR
                   (
                       100
                   ) UNIQUE NULLABLE,
                       reset_token_expires_at DATETIME NULLABLE
                       ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                   ''')
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS crushes
                   (
                       id
                       INT
                       AUTO_INCREMENT
                       PRIMARY
                       KEY,
                       user_id
                       INT
                       NOT
                       NULL,
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
                       notes TEXT,
                       FOREIGN KEY
                   (
                       user_id
                   ) REFERENCES users
                   (
                       id
                   ) ON DELETE CASCADE
                       ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                   ''')
    print("Checked/Created 'users' (updated with email/reset fields) and 'crushes' tables.")


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def add_user(cursor, cnx, username, email, password):
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise UserExistsError(f"Username '{username}' already exists.")
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            raise UserExistsError(f"Email '{email}' already registered.")
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
    cursor.execute("SELECT id, username, email, password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row: return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


def get_user_by_id(cursor, user_id):
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row: return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


def get_user_by_email(cursor, email):
    cursor.execute("SELECT id, username, email, password_hash FROM users WHERE email = ?", (email,))
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
        if err.errno == 1062:
            raise UserExistsError(f"Email '{email}' might already be in use.")
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
    if not row:
        return None

    columns = [desc[0] for desc in cursor.description]
    user = dict(zip(columns, row))

    if user['reset_token_expires_at'] < datetime.datetime.utcnow():
        return None
    return user


def reset_user_password(cursor, cnx, user_id, new_password):
    hashed_pwd = hash_password(new_password)
    try:
        cursor.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?",
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
    if str_value not in ['male', 'female', 'other']:
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


def list_all_crushes_for_user(cursor, user_id, page=1, limit=10, sort_by='id', sort_order='asc', filters=None):
    query_params = [user_id]
    base_query = "SELECT * FROM crushes WHERE user_id = ?"

    filter_clauses = []
    if filters:
        if 'gender' in filters and filters['gender']:
            filter_clauses.append("gender = ?")
            query_params.append(filters['gender'])
        if 'name_contains' in filters and filters['name_contains']:
            filter_clauses.append("(first_name LIKE ? OR last_name LIKE ?)")
            query_params.append(f"%{filters['name_contains']}%")
            query_params.append(f"%{filters['name_contains']}%")

    if filter_clauses:
        base_query += " AND " + " AND ".join(filter_clauses)

    allowed_sort_columns = ['id', 'first_name', 'last_name', 'acquaintance_date', 'age', 'relationship_status',
                            'interaction_level', 'feelings_level']
    if sort_by not in allowed_sort_columns:
        sort_by = 'id'

    sort_order_sql = "ASC" if sort_order.lower() == 'asc' else "DESC"
    base_query += f" ORDER BY {sort_by} {sort_order_sql}"

    offset = (page - 1) * limit
    base_query += " LIMIT ? OFFSET ?"
    query_params.extend([limit, offset])

    cursor.execute(base_query, tuple(query_params))
    rows = cursor.fetchall()

    count_query = "SELECT COUNT(*) FROM crushes WHERE user_id = ?"
    count_params_list = [user_id]  # Use a list to append filter parameters

    current_query_param_index = 1  # Start after user_id for filters
    if filter_clauses:
        count_query += " AND " + " AND ".join(filter_clauses)
        for filter_clause in filter_clauses:
            num_placeholders_in_clause = filter_clause.count('?')
            for _ in range(num_placeholders_in_clause):
                count_params_list.append(query_params[current_query_param_index])
                current_query_param_index += 1

    cursor.execute(count_query, tuple(count_params_list))
    total_count = cursor.fetchone()[0]

    if not rows:
        return [], total_count

    columns = [desc[0] for desc in cursor.description]
    results = [dict(zip(columns, row)) for row in rows]
    return results, total_count


def get_crush_details_for_user(cursor, crush_id, user_id):
    query = "SELECT * FROM crushes WHERE id = ? AND user_id = ?"
    cursor.execute(query, (crush_id, user_id))
    row = cursor.fetchone()
    if not row:
        raise NotFoundError(f"Crush with ID {crush_id} not found or not accessible by this user.")
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


def create_new_crush_for_user(cursor, cnx, crush_data, user_id):
    first_name = validate_text_field(crush_data.get('first_name'), 'first_name', max_length=255, allow_null=False)
    last_name = validate_text_field(crush_data.get('last_name'), 'last_name', max_length=255, allow_null=True)
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
                       INSERT INTO crushes (user_id, first_name, last_name, gender, acquaintance_date, age, \
                                            phone_number, instagram_id,
                                            relationship_status, interaction_level, feelings_level,
                                            future_plan, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                       """
    record_to_insert = (
        user_id, first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
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

    crush_fields = {
        'first_name': lambda val: validate_text_field(val, 'first_name', max_length=255, allow_null=False),
        'last_name': lambda val: validate_text_field(val, 'last_name', max_length=255, allow_null=True),
        'gender': lambda val: validate_gender_field(val, 'gender', allow_null=True),
        'acquaintance_date': lambda val: validate_date_field(val, 'acquaintance_date', allow_null=True),
        'age': lambda val: validate_integer_field(val, 'age', min_val=0, max_val=120, allow_null=True),
        'phone_number': lambda val: validate_text_field(val, 'phone_number', max_length=20, allow_null=True),
        'instagram_id': lambda val: validate_text_field(val, 'instagram_id', max_length=50, allow_null=True),
        'relationship_status': lambda val: validate_text_field(val, 'relationship_status', max_length=50,
                                                               allow_null=True),
        'interaction_level': lambda val: validate_integer_field(val, 'interaction_level', min_val=1, max_val=5,
                                                                allow_null=True),
        'feelings_level': lambda val: validate_integer_field(val, 'feelings_level', min_val=1, max_val=5,
                                                             allow_null=True),
        'future_plan': lambda val: validate_text_field(val, 'future_plan', max_length=255, allow_null=True),
        'notes': lambda val: validate_text_field(val, 'notes', allow_null=True)
    }

    for field, validator in crush_fields.items():
        if field in update_data:
            set_clauses.append(f"{field} = ?")
            updated_values.append(validator(update_data[field]))

    if not set_clauses:
        raise ValueError("No valid fields provided for update.")

    update_sql_query = f"UPDATE crushes SET {', '.join(set_clauses)} WHERE id = ? AND user_id = ?"
    updated_values.extend([crush_id, user_id])
    try:
        cursor.execute(update_sql_query, tuple(updated_values))
        cnx.commit()
        if cursor.rowcount == 0:
            cursor.execute("SELECT id FROM crushes WHERE id = ?", (crush_id,))
            if not cursor.fetchone():
                raise NotFoundError(f"Crush with ID {crush_id} not found.")
            else:
                raise UnauthorizedError(f"User not authorized to update crush ID {crush_id}, or no changes were made.")
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
