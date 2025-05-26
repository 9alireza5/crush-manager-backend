import mysql.connector
import datetime

class NotFoundError(Exception):
    pass

def get_db_connection():
    db_password = ""
    try:
        cnx = mysql.connector.connect(
            host="localhost",
            user="alirezza",
            password=db_password,
            database="learningdb"
        )
        return cnx
    except mysql.connector.Error as err:
        raise err

def validate_text_field(value, field_name, max_length=None, allow_null=True):
    if value is None and allow_null:
        return None
    if value is None and not allow_null:
        raise ValueError(f"'{field_name}' cannot be null.")
    
    str_value = str(value).strip()
    if str_value == "" and allow_null:
        return None
    if str_value == "" and not allow_null:
        raise ValueError(f"'{field_name}' cannot be empty.")
        
    if max_length and len(str_value) > max_length:
        raise ValueError(f"'{field_name}' exceeds maximum length of {max_length} characters.")
    return str_value

def validate_integer_field(value, field_name, min_val=None, max_val=None, allow_null=True):
    if value is None and allow_null:
        return None
    if value is None and not allow_null:
        raise ValueError(f"'{field_name}' cannot be null.")

    try:
        if isinstance(value, str) and value.strip() == "" and allow_null:
            return None
        if isinstance(value, str) and value.strip() == "" and not allow_null:
             raise ValueError(f"'{field_name}' cannot be empty.")

        int_value = int(value)
        if min_val is not None and int_value < min_val:
            raise ValueError(f"'{field_name}' must be at least {min_val}.")
        if max_val is not None and int_value > max_val:
            raise ValueError(f"'{field_name}' must be at most {max_val}.")
        return int_value
    except (ValueError, TypeError) as e:
        raise ValueError(f"'{field_name}' is not a valid integer. Original error: {e}")


def validate_gender_field(value, field_name, allow_null=True):
    if value is None and allow_null:
        return None
    if value is None and not allow_null:
        raise ValueError(f"'{field_name}' cannot be null.")

    str_value = str(value).strip().lower()
    if str_value == "" and allow_null:
        return None
    if str_value == "" and not allow_null:
        raise ValueError(f"'{field_name}' cannot be empty.")

    if str_value not in ['male', 'female']:
        raise ValueError(f"'{field_name}' must be 'male' or 'female'.")
    return str_value

def validate_date_field(value, field_name, allow_null=True):
    if value is None and allow_null:
        return None
    if value is None and not allow_null:
        raise ValueError(f"'{field_name}' cannot be null.")

    str_value = str(value).strip()
    if str_value == "" and allow_null:
        return None
    if str_value == "" and not allow_null:
        raise ValueError(f"'{field_name}' cannot be empty.")
        
    try:
        datetime.datetime.strptime(str_value, '%Y-%m-%d')
        return str_value
    except ValueError:
        raise ValueError(f"'{field_name}' has an invalid date format. Please use YYYY-MM-DD.")

def list_all_crushes(cursor):
    query = (
        "SELECT id, first_name, last_name, gender, acquaintance_date, age, "
        "phone_number, instagram_id, relationship_status, interaction_level, "
        "feelings_level, future_plan, notes FROM crushes"
    )
    cursor.execute(query)
    rows = cursor.fetchall()
    if not rows:
        return []
    
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]

def get_crush_details(cursor, crush_id):
    query = (
        "SELECT id, first_name, last_name, gender, acquaintance_date, age, "
        "phone_number, instagram_id, relationship_status, interaction_level, "
        "feelings_level, future_plan, notes FROM crushes WHERE id = %s"
    )
    cursor.execute(query, (crush_id,))
    row = cursor.fetchone()
    if not row:
        raise NotFoundError(f"Crush with ID {crush_id} not found.")
    
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))

def create_new_crush(cursor, cnx, crush_data):
    first_name = validate_text_field(crush_data.get('first_name'), 'first_name', max_length=15, allow_null=False) # Example: make first_name required
    last_name = validate_text_field(crush_data.get('last_name'), 'last_name', max_length=15, allow_null=True)
    gender = validate_gender_field(crush_data.get('gender'), 'gender', allow_null=True)
    acquaintance_date = validate_date_field(crush_data.get('acquaintance_date'), 'acquaintance_date', allow_null=True)
    age = validate_integer_field(crush_data.get('age'), 'age', min_val=0, max_val=120, allow_null=True)
    phone_number = validate_text_field(crush_data.get('phone_number'), 'phone_number', max_length=20, allow_null=True)
    instagram_id = validate_text_field(crush_data.get('instagram_id'), 'instagram_id', max_length=50, allow_null=True)
    relationship_status = validate_text_field(crush_data.get('relationship_status'), 'relationship_status', max_length=50, allow_null=True)
    interaction_level = validate_integer_field(crush_data.get('interaction_level'), 'interaction_level', min_val=1, max_val=5, allow_null=True)
    feelings_level = validate_integer_field(crush_data.get('feelings_level'), 'feelings_level', min_val=1, max_val=5, allow_null=True)
    future_plan = validate_text_field(crush_data.get('future_plan'), 'future_plan', max_length=50, allow_null=True)
    notes = validate_text_field(crush_data.get('notes'), 'notes', allow_null=True)

    insert_sql_query = """
        INSERT INTO crushes (first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
                             relationship_status, interaction_level, feelings_level,
                             future_plan, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    record_to_insert = (
        first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
        relationship_status, interaction_level, feelings_level,
        future_plan, notes
    )

    try:
        cursor.execute(insert_sql_query, record_to_insert)
        cnx.commit()
        return cursor.lastrowid
    except mysql.connector.Error as err:
        cnx.rollback()
        raise err

def update_existing_crush(cursor, cnx, crush_id, update_data):
    get_crush_details(cursor, crush_id) # Check existence, will raise NotFoundError if not found

    set_clauses = []
    updated_values = []

    if 'first_name' in update_data:
        set_clauses.append("first_name = %s")
        updated_values.append(validate_text_field(update_data['first_name'], 'first_name', max_length=15, allow_null=False))
    if 'last_name' in update_data:
        set_clauses.append("last_name = %s")
        updated_values.append(validate_text_field(update_data['last_name'], 'last_name', max_length=15))
    if 'gender' in update_data:
        set_clauses.append("gender = %s")
        updated_values.append(validate_gender_field(update_data['gender'], 'gender'))
    if 'acquaintance_date' in update_data:
        set_clauses.append("acquaintance_date = %s")
        updated_values.append(validate_date_field(update_data['acquaintance_date'], 'acquaintance_date'))
    if 'age' in update_data:
        set_clauses.append("age = %s")
        updated_values.append(validate_integer_field(update_data['age'], 'age', min_val=0, max_val=120))
    if 'phone_number' in update_data:
        set_clauses.append("phone_number = %s")
        updated_values.append(validate_text_field(update_data['phone_number'], 'phone_number', max_length=20))
    if 'instagram_id' in update_data:
        set_clauses.append("instagram_id = %s")
        updated_values.append(validate_text_field(update_data['instagram_id'], 'instagram_id', max_length=50))
    if 'relationship_status' in update_data:
        set_clauses.append("relationship_status = %s")
        updated_values.append(validate_text_field(update_data['relationship_status'], 'relationship_status', max_length=50))
    if 'interaction_level' in update_data:
        set_clauses.append("interaction_level = %s")
        updated_values.append(validate_integer_field(update_data['interaction_level'], 'interaction_level', min_val=1, max_val=5))
    if 'feelings_level' in update_data:
        set_clauses.append("feelings_level = %s")
        updated_values.append(validate_integer_field(update_data['feelings_level'], 'feelings_level', min_val=1, max_val=5))
    if 'future_plan' in update_data:
        set_clauses.append("future_plan = %s")
        updated_values.append(validate_text_field(update_data['future_plan'], 'future_plan', max_length=50))
    if 'notes' in update_data:
        set_clauses.append("notes = %s")
        updated_values.append(validate_text_field(update_data['notes'], 'notes', allow_null=True))

    if not set_clauses:
        raise ValueError("No valid fields provided for update.")

    update_sql_query = f"UPDATE crushes SET {', '.join(set_clauses)} WHERE id = %s"
    updated_values.append(crush_id)

    try:
        cursor.execute(update_sql_query, tuple(updated_values))
        cnx.commit()
        return cursor.rowcount
    except mysql.connector.Error as err:
        cnx.rollback()
        raise err

def delete_existing_crush(cursor, cnx, crush_id):
    get_crush_details(cursor, crush_id) # Check existence

    delete_sql_query = "DELETE FROM crushes WHERE id = %s"
    try:
        cursor.execute(delete_sql_query, (crush_id,))
        cnx.commit()
        return cursor.rowcount
    except mysql.connector.Error as err:
        cnx.rollback()
        raise err
