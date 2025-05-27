import mariadb
import datetime


class NotFoundError(Exception):
    # Custom exception for when a record is not found.
    pass


def get_db_connection():
    # IMPORTANT: For production, use a strong password and consider environment variables
    # or a config file for credentials instead of hardcoding.
    db_password = "awx2er0fRBTFD1uKQjEXze4Q"
    try:
        # Using mariadb.connect
        cnx = mariadb.connect(
            host="localhost",
            user="alirezza",  # Ensure this user exists and has the necessary permissions
            password=db_password,
            database="learningdb",  # Ensure this database exists
            port=3306  # Default MariaDB/MySQL port, change if necessary
        )
        return cnx
    except mariadb.Error as err:  # Changed from mysql.connector.Error
        # Log this error or handle it more gracefully as needed
        print(f"Database connection error: {err}")
        raise  # Re-raise the exception to be caught by the caller


def validate_text_field(value, field_name, max_length=None, allow_null=True):
    # Validates a text field.
    if value is None:
        if allow_null:
            return None
        else:
            raise ValueError(f"'{field_name}' cannot be null.")

    str_value = str(value).strip()
    if not str_value:  # Handles empty string after strip
        if allow_null:
            return None  # Treat empty string as null if allowed
        else:
            raise ValueError(f"'{field_name}' cannot be empty.")

    if max_length and len(str_value) > max_length:
        raise ValueError(f"'{field_name}' exceeds maximum length of {max_length} characters.")
    return str_value


def validate_integer_field(value, field_name, min_val=None, max_val=None, allow_null=True):
    # Validates an integer field.
    if value is None:
        if allow_null:
            return None
        else:
            raise ValueError(f"'{field_name}' cannot be null.")

    if isinstance(value, str):
        str_value = value.strip()
        if not str_value:  # Handles empty string after strip
            if allow_null:
                return None  # Treat empty string as null if allowed
            else:
                raise ValueError(f"'{field_name}' cannot be empty.")
    else:  # value is not a string (could be int, float etc.)
        str_value = str(value)  # Convert to string to handle non-string, non-None types

    try:
        int_value = int(str_value)  # Use str_value which has been stripped if originally string
        if min_val is not None and int_value < min_val:
            raise ValueError(f"'{field_name}' must be at least {min_val}.")
        if max_val is not None and int_value > max_val:
            raise ValueError(f"'{field_name}' must be at most {max_val}.")
        return int_value
    except ValueError:  # Catches int conversion error
        raise ValueError(f"'{field_name}' is not a valid integer.")


def validate_gender_field(value, field_name, allow_null=True):
    # Validates the gender field.
    if value is None:
        if allow_null:
            return None
        else:
            raise ValueError(f"'{field_name}' cannot be null.")

    str_value = str(value).strip().lower()
    if not str_value:  # Handles empty string after strip
        if allow_null:
            return None  # Treat empty string as null if allowed
        else:
            raise ValueError(f"'{field_name}' cannot be empty.")

    if str_value not in ['male', 'female']:
        raise ValueError(f"'{field_name}' must be 'male' or 'female'.")
    return str_value


def validate_date_field(value, field_name, allow_null=True):
    # Validates a date field string.
    if value is None:
        if allow_null:
            return None
        else:
            raise ValueError(f"'{field_name}' cannot be null.")

    str_value = str(value).strip()
    if not str_value:  # Handles empty string after strip
        if allow_null:
            return None  # Treat empty string as null if allowed
        else:
            raise ValueError(f"'{field_name}' cannot be empty.")

    try:
        # Validate format, but return the string as database expects a string for DATE type
        datetime.datetime.strptime(str_value, '%Y-%m-%d')
        return str_value
    except ValueError:
        raise ValueError(f"'{field_name}' has an invalid date format. Please use YYYY-MM-DD.")


def list_all_crushes(cursor):
    # Retrieves all crushes from the database.
    query = (
        "SELECT id, first_name, last_name, gender, acquaintance_date, age, "
        "phone_number, instagram_id, relationship_status, interaction_level, "
        "feelings_level, future_plan, notes FROM crushes"
    )
    cursor.execute(query)
    rows = cursor.fetchall()
    if not rows:
        return []  # Return empty list if no crushes found

    # Convert rows to list of dictionaries
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]


def get_crush_details(cursor, crush_id):
    # Retrieves details for a specific crush by ID.
    query = (
        "SELECT id, first_name, last_name, gender, acquaintance_date, age, "
        "phone_number, instagram_id, relationship_status, interaction_level, "
        "feelings_level, future_plan, notes FROM crushes WHERE id = ?"  # Changed %s to ? for mariadb
    )
    cursor.execute(query, (crush_id,))
    row = cursor.fetchone()
    if not row:
        raise NotFoundError(f"Crush with ID {crush_id} not found.")

    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))


def create_new_crush(cursor, cnx, crush_data):
    # Creates a new crush record in the database.
    first_name = validate_text_field(crush_data.get('first_name'), 'first_name', max_length=15, allow_null=False)
    last_name = validate_text_field(crush_data.get('last_name'), 'last_name', max_length=15, allow_null=True)
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
    future_plan = validate_text_field(crush_data.get('future_plan'), 'future_plan', max_length=50, allow_null=True)
    notes = validate_text_field(crush_data.get('notes'), 'notes',
                                allow_null=True)  # Consider a larger max_length for notes depending on DB schema

    insert_sql_query = """
                       INSERT INTO crushes (first_name, last_name, gender, acquaintance_date, age, phone_number, \
                                            instagram_id,
                                            relationship_status, interaction_level, feelings_level,
                                            future_plan, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                       """  # Changed %s to ? for mariadb
    record_to_insert = (
        first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
        relationship_status, interaction_level, feelings_level,
        future_plan, notes
    )

    try:
        cursor.execute(insert_sql_query, record_to_insert)
        cnx.commit()
        return cursor.lastrowid  # Returns the ID of the newly inserted row
    except mariadb.Error as err:  # Changed from mysql.connector.Error
        cnx.rollback()  # Rollback in case of error
        raise  # Re-raise the exception


def update_existing_crush(cursor, cnx, crush_id, update_data):
    # Updates an existing crush record.
    # First, check if the crush exists. This will raise NotFoundError if not.
    get_crush_details(cursor, crush_id)

    set_clauses = []
    updated_values = []

    # For each field, if it's in update_data, validate and add to query
    if 'first_name' in update_data:
        set_clauses.append("first_name = ?")  # Changed %s to ?
        updated_values.append(
            validate_text_field(update_data['first_name'], 'first_name', max_length=15, allow_null=False))
    if 'last_name' in update_data:
        set_clauses.append("last_name = ?")  # Changed %s to ?
        updated_values.append(
            validate_text_field(update_data['last_name'], 'last_name', max_length=15, allow_null=True))
    if 'gender' in update_data:
        set_clauses.append("gender = ?")
        updated_values.append(validate_gender_field(update_data['gender'], 'gender', allow_null=True))
    if 'acquaintance_date' in update_data:
        set_clauses.append("acquaintance_date = ?")
        updated_values.append(
            validate_date_field(update_data['acquaintance_date'], 'acquaintance_date', allow_null=True))
    if 'age' in update_data:
        set_clauses.append("age = ?")
        updated_values.append(
            validate_integer_field(update_data['age'], 'age', min_val=0, max_val=120, allow_null=True))
    if 'phone_number' in update_data:
        set_clauses.append("phone_number = ?")
        updated_values.append(
            validate_text_field(update_data['phone_number'], 'phone_number', max_length=20, allow_null=True))
    if 'instagram_id' in update_data:
        set_clauses.append("instagram_id = ?")
        updated_values.append(
            validate_text_field(update_data['instagram_id'], 'instagram_id', max_length=50, allow_null=True))
    if 'relationship_status' in update_data:
        set_clauses.append("relationship_status = ?")
        updated_values.append(
            validate_text_field(update_data['relationship_status'], 'relationship_status', max_length=50,
                                allow_null=True))
    if 'interaction_level' in update_data:
        set_clauses.append("interaction_level = ?")
        updated_values.append(
            validate_integer_field(update_data['interaction_level'], 'interaction_level', min_val=1, max_val=5,
                                   allow_null=True))
    if 'feelings_level' in update_data:
        set_clauses.append("feelings_level = ?")
        updated_values.append(
            validate_integer_field(update_data['feelings_level'], 'feelings_level', min_val=1, max_val=5,
                                   allow_null=True))
    if 'future_plan' in update_data:
        set_clauses.append("future_plan = ?")
        updated_values.append(
            validate_text_field(update_data['future_plan'], 'future_plan', max_length=50, allow_null=True))
    if 'notes' in update_data:
        set_clauses.append("notes = ?")
        updated_values.append(validate_text_field(update_data['notes'], 'notes', allow_null=True))

    if not set_clauses:
        # No valid fields were provided for update.
        raise ValueError("No valid fields provided for update or all values are unchanged.")

    update_sql_query = f"UPDATE crushes SET {', '.join(set_clauses)} WHERE id = ?"  # Changed %s to ? for the WHERE clause
    updated_values.append(crush_id)  # Add crush_id for the WHERE clause

    try:
        cursor.execute(update_sql_query, tuple(updated_values))
        cnx.commit()
        return cursor.rowcount  # Number of rows affected
    except mariadb.Error as err:  # Changed from mysql.connector.Error
        cnx.rollback()
        raise err


def delete_existing_crush(cursor, cnx, crush_id):
    # Deletes an existing crush record.
    # Check existence first. If not found, NotFoundError will be raised.
    get_crush_details(cursor, crush_id)

    delete_sql_query = "DELETE FROM crushes WHERE id = ?"  # Changed %s to ?
    try:
        cursor.execute(delete_sql_query, (crush_id,))
        cnx.commit()
        # After a successful get_crush_details, rowcount should be 1 if deletion was successful.
        # If rowcount is 0 here, it implies the record disappeared between check and delete (race condition)
        # or some other unexpected issue.
        if cursor.rowcount == 0:
            # This case is unusual if get_crush_details succeeded.
            # It implies the record was there, but deletion affected 0 rows.
            raise NotFoundError(f"Crush with ID {crush_id} was found but could not be deleted (0 rows affected).")
        return cursor.rowcount
    except mariadb.Error as err:  # Changed from mysql.connector.Error
        cnx.rollback()
        raise err
