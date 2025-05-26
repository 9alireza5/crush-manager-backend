import mysql.connector
import datetime


def get_text_input(prompt_message, max_length=None, allow_none=True):
    while True:
        user_input = input(prompt_message).strip()
        if user_input == "" and allow_none:
            return None
        if user_input.upper() == "NULL" and allow_none:
            return None
        if max_length and len(user_input) > max_length:
            print(f"Error: Input exceeds maximum length of {max_length} characters. Please try again.")
        else:
            return user_input


def get_integer_input(prompt_message, min_val=None, max_val=None, allow_none=True):
    while True:
        user_input = input(prompt_message).strip()
        if user_input == "" and allow_none:
            return None
        if user_input.upper() == "NULL" and allow_none:
            return None
        try:
            value = int(user_input)
            if min_val is not None and value < min_val:
                print(f"Error: Value must be at least {min_val}. Please try again.")
            elif max_val is not None and value > max_val:
                print(f"Error: Value must be at most {max_val}. Please try again.")
            else:
                return value
        except ValueError:
            print(
                f"Error: Input '{user_input}' is not a valid integer. Please enter a number, 'NULL', or press Enter for NULL.")


def get_gender_input(prompt_message, allow_none=True):
    while True:
        gender_input = input(prompt_message).strip().lower()
        if gender_input == "" and allow_none:
            return None
        if gender_input.upper() == "NULL" and allow_none:
            return None
        if gender_input in ['male', 'female']:
            return gender_input
        else:
            print("Invalid value. Please enter 'male', 'female', 'NULL', or press Enter for NULL.")


def get_date_input(prompt_message, allow_none=True):
    while True:
        user_input = input(prompt_message).strip()
        if user_input == "" and allow_none:
            return None
        if user_input.upper() == "NULL" and allow_none:
            return None
        try:
            datetime.datetime.strptime(user_input, '%Y-%m-%d')
            return user_input
        except ValueError:
            print(f"Error: Invalid date format. Please use YYYY-MM-DD, 'NULL', or press Enter for NULL.")


def get_input_with_validation(prompt_prefix, current_value, validation_func, *args, **kwargs):
    current_display = "NULL" if current_value is None else str(current_value)
    prompt = f"{prompt_prefix} (current: {current_display}, Enter to keep, 'NULL' to set NULL): "

    while True:
        user_input = input(prompt).strip()
        if user_input == "":
            return current_value
        if user_input.upper() == "NULL":
            return None

        try:
            if validation_func == get_text_input:
                max_length = kwargs.get('max_length')
                if max_length and len(user_input) > max_length:
                    raise ValueError(f"Input exceeds maximum length of {max_length} characters.")
                return user_input
            elif validation_func == get_integer_input:
                min_val = kwargs.get('min_val')
                max_val = kwargs.get('max_val')
                value = int(user_input)
                if min_val is not None and value < min_val:
                    raise ValueError(f"Value must be at least {min_val}.")
                if max_val is not None and value > max_val:
                    raise ValueError(f"Value must be at most {max_val}.")
                return value
            elif validation_func == get_gender_input:
                if user_input.lower() not in ['male', 'female']:
                    raise ValueError("Invalid gender. Must be 'male' or 'female'.")
                return user_input.lower()
            elif validation_func == get_date_input:
                datetime.datetime.strptime(user_input, '%Y-%m-%d')
                return user_input

        except ValueError as e:
            print(
                f"Validation error: {e}. The input was '{user_input}'. Please try again, starting with the prompt below.")
        except Exception as e:
            print(f"An unexpected error occurred during input validation: {e}. Please try again.")


def display_crushes(cursor):
    print("\nFetching list of crushes...")
    # NEW SELECT ORDER: acquaintance_date moved after gender
    cursor.execute(
        "SELECT id, first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id, relationship_status, interaction_level, feelings_level, future_plan, notes FROM crushes"
    )
    all_crushes = cursor.fetchall()

    if not all_crushes:
        print("No crushes found in the database.")
        return None

    print("\n--- List of Your Crushes ---")
    # NEW COL_WIDTHS ORDER and potentially new key for acquaintance_date
    COL_WIDTHS = {
        'ID': 5,
        'First Name': 15,
        'Last Name': 15,
        'Gender': 10,
        'Acq. Date': 12,  # Moved and renamed from 'Acquainted'
        'Age': 5,
        'Phone': 15,
        'Instagram': 20,
        'Relationship': 20,
        'Interaction Lvl': 15,
        'Feelings Lvl': 12,
        'Future Plan': 20,
        'Notes': 30
    }

    header_parts = [f"{col_name:<{COL_WIDTHS[col_name]}}" for col_name in COL_WIDTHS]  # Order from COL_WIDTHS
    header = " | ".join(header_parts)
    print(header)
    print("-" * (sum(COL_WIDTHS.values()) + (len(COL_WIDTHS) - 1) * 3))

    # New indices for formatted_row based on the new SELECT order:
    # 0: id
    # 1: first_name
    # 2: last_name
    # 3: gender
    # 4: acquaintance_date  <-- NEW POSITION in SELECT
    # 5: age
    # 6: phone_number
    # 7: instagram_id
    # 8: relationship_status
    # 9: interaction_level
    # 10: feelings_level
    # 11: future_plan
    # 12: notes

    for row_data in all_crushes:
        formatted_row = [str(value) if value is not None else 'NULL' for value in row_data]

        # Build display_values based on the order in COL_WIDTHS and map to correct formatted_row index
        display_values = []
        display_values.append(f"{formatted_row[0]:<{COL_WIDTHS['ID']}}")
        display_values.append(f"{formatted_row[1]:<{COL_WIDTHS['First Name']}}")
        display_values.append(f"{formatted_row[2]:<{COL_WIDTHS['Last Name']}}")
        display_values.append(f"{formatted_row[3]:<{COL_WIDTHS['Gender']}}")
        display_values.append(f"{formatted_row[4]:<{COL_WIDTHS['Acq. Date']}}")  # acquaintance_date is now at index 4
        display_values.append(f"{formatted_row[5]:<{COL_WIDTHS['Age']}}")  # age is now at index 5
        display_values.append(f"{formatted_row[6]:<{COL_WIDTHS['Phone']}}")  # phone_number is now at index 6
        display_values.append(f"{formatted_row[7]:<{COL_WIDTHS['Instagram']}}")  # instagram_id is now at index 7

        relationship_status = formatted_row[8]  # relationship_status is now at index 8
        if len(relationship_status) > COL_WIDTHS['Relationship']:
            relationship_status = relationship_status[:COL_WIDTHS['Relationship'] - 3] + '...'
        display_values.append(f"{relationship_status:<{COL_WIDTHS['Relationship']}}")

        display_values.append(
            f"{formatted_row[9]:<{COL_WIDTHS['Interaction Lvl']}}")  # interaction_level is now at index 9
        display_values.append(f"{formatted_row[10]:<{COL_WIDTHS['Feelings Lvl']}}")  # feelings_level is now at index 10

        future_plan = formatted_row[11]  # future_plan is now at index 11
        if len(future_plan) > COL_WIDTHS['Future Plan']:
            future_plan = future_plan[:COL_WIDTHS['Future Plan'] - 3] + '...'
        display_values.append(f"{future_plan:<{COL_WIDTHS['Future Plan']}}")

        notes = formatted_row[12]  # notes is now at index 12
        if len(notes) > COL_WIDTHS['Notes']:
            notes = notes[:COL_WIDTHS['Notes'] - 3] + '...'
        display_values.append(f"{notes:<{COL_WIDTHS['Notes']}}")

        print(" | ".join(display_values))

    print("-" * (sum(COL_WIDTHS.values()) + (len(COL_WIDTHS) - 1) * 3))
    return all_crushes


def view_single_crush(cursor):
    print("\n--- View Single Crush ---")
    all_crushes_data = display_crushes(cursor)  # This will now fetch with new order

    if not all_crushes_data:
        return

    try:
        view_id = get_integer_input("Enter the ID of the crush you want to view: ", allow_none=False)
        if view_id is None:
            print("Invalid input. Please enter a valid ID.")
            return

        selected_crush = None
        for crush_row in all_crushes_data:  # Renamed to avoid confusion
            if crush_row[0] == view_id:  # id is still at index 0
                selected_crush = crush_row
                break

        if not selected_crush:
            print("No crush found with that ID.")
            return

    except ValueError:
        print("Invalid input. Please enter a number for the ID.")
        return

    # New indices for selected_crush based on the new SELECT order:
    # 0: id
    # 1: first_name
    # 2: last_name
    # 3: gender
    # 4: acquaintance_date
    # 5: age
    # 6: phone_number
    # 7: instagram_id
    # 8: relationship_status
    # 9: interaction_level
    # 10: feelings_level
    # 11: future_plan
    # 12: notes
    print(f"\n--- Details for {selected_crush[1]} {selected_crush[2]} ---")
    print(f"ID:                  {selected_crush[0] if selected_crush[0] is not None else 'NULL'}")
    print(f"First Name:          {selected_crush[1] if selected_crush[1] is not None else 'NULL'}")
    print(f"Last Name:           {selected_crush[2] if selected_crush[2] is not None else 'NULL'}")
    print(f"Gender:              {selected_crush[3] if selected_crush[3] is not None else 'NULL'}")
    print(f"Acquaintance Date:   {selected_crush[4] if selected_crush[4] is not None else 'NULL'}")  # Moved up
    print(f"Age:                 {selected_crush[5] if selected_crush[5] is not None else 'NULL'}")  # Index shifted
    print(f"Phone Number:        {selected_crush[6] if selected_crush[6] is not None else 'NULL'}")  # Index shifted
    print(f"Instagram ID:        {selected_crush[7] if selected_crush[7] is not None else 'NULL'}")  # Index shifted
    print(f"Relationship Status: {selected_crush[8] if selected_crush[8] is not None else 'NULL'}")  # Index shifted
    print(f"Interaction Level:   {selected_crush[9] if selected_crush[9] is not None else 'NULL'}")  # Index shifted
    print(f"Feelings Level:      {selected_crush[10] if selected_crush[10] is not None else 'NULL'}")  # Index shifted
    print(f"Future Plan:         {selected_crush[11] if selected_crush[11] is not None else 'NULL'}")  # Index shifted
    print(f"Notes:               {selected_crush[12] if selected_crush[12] is not None else 'NULL'}")  # Index shifted
    print("---------------------------------------")


def add_new_crush(cursor, cnx):
    print("\n--- Add New Crush ---")
    print("Please enter the new crush's information (press Enter to skip a field for NULL):")

    first_name = get_text_input("First name (text, max 15 characters): ", max_length=15)
    last_name = get_text_input("Last name (text, max 15 characters): ", max_length=15)
    gender = get_gender_input("Gender ('male' or 'female', or press Enter for NULL): ")
    # Input order for user does not need to change unless desired
    acquaintance_date = get_date_input("Acquaintance date (YYYY-MM-DD, or press Enter for NULL): ")
    age = get_integer_input("Age (integer, e.g., 28): ", min_val=0, max_val=120)
    phone_number = get_text_input("Phone number (text, max 20 characters): ", max_length=20)
    instagram_id = get_text_input("Instagram ID (text, max 50 characters): ", max_length=50)
    relationship_status = get_text_input("Relationship status (text, max 50 chars): ", max_length=50)
    interaction_level = get_integer_input("Interaction level (integer, 1-5): ", min_val=1, max_val=5)
    feelings_level = get_integer_input("Feelings level (integer, 1-5): ", min_val=1, max_val=5)
    future_plan = get_text_input("Future plan (text, max 50 chars): ", max_length=50)
    notes = get_text_input("Additional notes (long text): ")

    # INSERT query column order must match value order in record_to_insert
    # The order of columns in INSERT statement should match the physical order in DB or a desired logical order for the INSERT statement
    # It doesn't have to strictly match the SELECT order for display, but consistency is good.
    # Let's match the new SELECT order for the INSERT statement columns for clarity.
    insert_sql_query = """
                       INSERT INTO crushes (first_name, last_name, gender, acquaintance_date, age, phone_number, \
                                            instagram_id,
                                            relationship_status, interaction_level, feelings_level,
                                            future_plan, notes)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) \
                       """
    # id is auto-increment, not inserted explicitly
    record_to_insert = (
        first_name, last_name, gender, acquaintance_date, age, phone_number, instagram_id,
        relationship_status, interaction_level, feelings_level,
        future_plan, notes
    )

    try:
        cursor.execute(insert_sql_query, record_to_insert)
        cnx.commit()
        print(f"\n{cursor.rowcount} record inserted successfully into crushes table.")
    except mysql.connector.Error as err:
        print(f"Error inserting record: {err}")
        cnx.rollback()


def edit_existing_crush(cursor, cnx):
    print("\n--- Edit Existing Crush ---")
    all_crushes_data = display_crushes(cursor)  # Fetches with new SELECT order

    if not all_crushes_data:
        return

    try:
        edit_id = get_integer_input("Enter the ID of the crush you want to edit: ", allow_none=False)
        if edit_id is None:
            print("Invalid input. Please enter a valid ID.")
            return

        selected_crush_original_data = None
        for crush_row in all_crushes_data:
            if crush_row[0] == edit_id:
                selected_crush_original_data = crush_row
                break

        if not selected_crush_original_data:
            print("No crush found with that ID.")
            return

    except ValueError:
        print("Invalid input. Please enter a number for the ID.")
        return

    original_first_name = selected_crush_original_data[1]  # first_name is at index 1
    original_last_name = selected_crush_original_data[2]  # last_name is at index 2

    print(f"\nEditing crush: {original_first_name} {original_last_name} (ID: {edit_id})")
    print(
        "For each field, enter the new value. Press Enter to keep the current value. Type 'NULL' to set field to NULL.")

    # Populate current_values_map based on the new SELECT order
    # 0: id, 1: first_name, 2: last_name, 3: gender, 4: acquaintance_date, 5: age, ...
    current_values_map = {
        "id": selected_crush_original_data[0],
        "First name": selected_crush_original_data[1],
        "Last name": selected_crush_original_data[2],
        "Gender": selected_crush_original_data[3],
        "Acquaintance date": selected_crush_original_data[4],  # New position
        "Age": selected_crush_original_data[5],  # Index shifted
        "Phone number": selected_crush_original_data[6],  # Index shifted
        "Instagram ID": selected_crush_original_data[7],  # Index shifted
        "Relationship status": selected_crush_original_data[8],  # Index shifted
        "Interaction level": selected_crush_original_data[9],  # Index shifted
        "Feelings level": selected_crush_original_data[10],  # Index shifted
        "Future plan": selected_crush_original_data[11],  # Index shifted
        "Notes": selected_crush_original_data[12]  # Index shifted
    }
    # The order of calls to get_input_with_validation can remain logical for user experience
    updated_first_name = get_input_with_validation("New First name", current_values_map['First name'], get_text_input,
                                                   max_length=15)
    updated_last_name = get_input_with_validation("New Last name", current_values_map['Last name'], get_text_input,
                                                  max_length=15)
    updated_gender = get_input_with_validation("New Gender ('male'/'female')", current_values_map['Gender'],
                                               get_gender_input)
    updated_acquaintance_date = get_input_with_validation("New Acquaintance date (YYYY-MM-DD)",
                                                          current_values_map['Acquaintance date'],
                                                          get_date_input)  # User input order
    updated_age = get_input_with_validation("New Age", current_values_map['Age'], get_integer_input, min_val=0,
                                            max_val=120)
    updated_phone_number = get_input_with_validation("New Phone number", current_values_map['Phone number'],
                                                     get_text_input, max_length=20)
    updated_instagram_id = get_input_with_validation("New Instagram ID", current_values_map['Instagram ID'],
                                                     get_text_input, max_length=50)
    updated_relationship_status = get_input_with_validation("New Relationship status",
                                                            current_values_map['Relationship status'], get_text_input,
                                                            max_length=50)
    updated_interaction_level = get_input_with_validation("New Interaction level (1-5)",
                                                          current_values_map['Interaction level'], get_integer_input,
                                                          min_val=1, max_val=5)
    updated_feelings_level = get_input_with_validation("New Feelings level (1-5)", current_values_map['Feelings level'],
                                                       get_integer_input, min_val=1, max_val=5)
    updated_future_plan = get_input_with_validation("New Future plan", current_values_map['Future plan'],
                                                    get_text_input, max_length=50)
    updated_notes = get_input_with_validation("New Notes", current_values_map['Notes'], get_text_input)

    # The UPDATE query's SET clause order does not need to change,
    # as long as the updated_values tuple matches the %s placeholders.
    update_sql_query = """
                       UPDATE crushes
                       SET first_name          = %s,
                           last_name           = %s,
                           gender              = %s,
                           acquaintance_date   = %s, /* Added to SET clause */
                           age                 = %s,
                           phone_number        = %s,
                           instagram_id        = %s,
                           relationship_status = %s,
                           interaction_level   = %s,
                           feelings_level      = %s,
                           future_plan         = %s,
                           notes               = %s
                       WHERE id = %s \
                       """
    # The order of items in updated_values tuple MUST match the %s in update_sql_query
    updated_values = (
        updated_first_name, updated_last_name, updated_gender,
        updated_acquaintance_date,  # Ensure this is in the correct spot for the SET clause
        updated_age,
        updated_phone_number, updated_instagram_id, updated_relationship_status,
        updated_interaction_level, updated_feelings_level, updated_future_plan,
        updated_notes, edit_id
    )

    try:
        cursor.execute(update_sql_query, updated_values)
        cnx.commit()

        if cursor.rowcount > 0:
            print(f"\nRecord for {original_first_name} {original_last_name} (ID: {edit_id}) updated successfully.")
        else:
            print(f"\nNo record found for ID: {edit_id} or no changes made.")
    except mysql.connector.Error as err:
        print(f"Error updating record: {err}")
        cnx.rollback()


def delete_crush(cursor, cnx):
    print("\n--- Delete Existing Crush ---")
    all_crushes_data = display_crushes(cursor)  # Fetches with new order, but delete only needs ID

    if not all_crushes_data:
        return

    try:
        delete_id = get_integer_input("Enter the ID of the crush you want to DELETE: ", allow_none=False)
        if delete_id is None:
            print("Invalid input. Please enter a valid ID.")
            return

        crush_to_delete = None
        for crush_row in all_crushes_data:
            if crush_row[0] == delete_id:  # id is still index 0
                crush_to_delete = crush_row
                break

        if not crush_to_delete:
            print("No crush found with that ID.")
            return

    except ValueError:
        print("Invalid input. Please enter a number for the ID.")
        return

    first_name = crush_to_delete[1]  # first_name is still index 1
    last_name = crush_to_delete[2]  # last_name is still index 2

    confirmation = input(
        f"Are you sure you want to delete {first_name} {last_name} (ID: {delete_id})? (yes/no): ").strip().lower()

    if confirmation == 'yes':
        delete_sql_query = "DELETE FROM crushes WHERE id = %s"
        try:
            cursor.execute(delete_sql_query, (delete_id,))
            cnx.commit()
            if cursor.rowcount > 0:
                print(f"Crush '{first_name} {last_name}' (ID: {delete_id}) deleted successfully.")
            else:
                print(f"Could not delete crush with ID '{delete_id}'.")
        except mysql.connector.Error as err:
            print(f"Error deleting record: {err}")
            cnx.rollback()
    else:
        print("Deletion cancelled.")


def main_application():
    db_connection = None
    db_cursor = None

    db_password = ""  # Assuming no password

    try:
        db_connection = mysql.connector.connect(
            host="localhost",
            user="alirezza",
            password=db_password,
            database="learningdb"
        )
        db_cursor = db_connection.cursor()
        print('\nConnected to MariaDB database.')

        while True:
            print("\n--- Crush Manager Menu ---")
            print("1. Add New Crush")
            print("2. Edit Existing Crush")
            print("3. View All Crushes")
            print("4. View Single Crush Details")
            print("5. Delete Crush")
            print("6. Exit")
            choice = input("Enter your choice (1-6): ")

            if choice == '1':
                add_new_crush(db_cursor, db_connection)
            elif choice == '2':
                edit_existing_crush(db_cursor, db_connection)
            elif choice == '3':
                display_crushes(db_cursor)
            elif choice == '4':
                view_single_crush(db_cursor)
            elif choice == '5':
                delete_crush(db_cursor, db_connection)
            elif choice == '6':
                print("Exiting application. Goodbye!")
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 6.")

    except mysql.connector.Error as db_error:
        print(f"Database connection error: {db_error}")
        if hasattr(db_error, 'errno') and db_error.errno == 1045:
            print(
                "Access Denied. Please ensure user 'alirezza' can connect from localhost with an empty password, or check other MariaDB user settings.")
        elif hasattr(db_error, 'errno') and db_error.errno == 2003:
            print(f"Can't connect to MariaDB server on 'localhost'. Is the server running?")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if db_cursor:
            db_cursor.close()
        if db_connection and db_connection.is_connected():
            db_connection.close()
            print('MariaDB connection closed.')


if __name__ == "__main__":
    main_application()