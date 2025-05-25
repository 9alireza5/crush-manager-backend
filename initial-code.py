import mysql.connector

def get_text_input_or_none(prompt_message):
    user_input = input(prompt_message).strip()
    if user_input == "":
        return None
    return user_input


def get_integer_input_or_none(prompt_message):
    user_input = input(prompt_message).strip()
    if user_input == "":
        return None
    try:
        return int(user_input)
    except ValueError:
        print(f"Error: Input '{user_input}' is not a valid integer. NULL will be stored instead.")
        return None


def get_gender_input_or_none(prompt_message):
    while True:
        gender_input = input(prompt_message).strip().lower()
        if gender_input == "":
            return None
        if gender_input in ['male', 'female']:
            return gender_input
        else:
            print("Invalid value. Please enter 'male' or 'female', or press Enter for NULL.")


def display_crushes(cursor):
    print("\nFetching list of crushes...")
    cursor.execute(
        "SELECT first_name, last_name, gender, age, phone_number, instagram_id, relationship_status, interaction_level, feelings_level, future_plan, notes FROM crushes")
    all_crushes = cursor.fetchall()

    if not all_crushes:
        print("No crushes found in the database.")
        return None

    print("\n--- List of Your Crushes ---")
    COL_WIDTHS = {
        'Index': 7,
        'First Name': 15,
        'Last Name': 15,
        'Gender': 10,
        'Age': 5,
        'Phone': 15,
        'Instagram': 20,
        'Relationship': 20,
        'Interaction Lvl': 15,
        'Feelings Lvl': 12,
        'Future Plan': 20,
        'Notes': 30
    }

    header = (
        f"{'Index':<{COL_WIDTHS['Index']}} | "
        f"{'First Name':<{COL_WIDTHS['First Name']}} | "
        f"{'Last Name':<{COL_WIDTHS['Last Name']}} | "
        f"{'Gender':<{COL_WIDTHS['Gender']}} | "
        f"{'Age':<{COL_WIDTHS['Age']}} | "
        f"{'Phone':<{COL_WIDTHS['Phone']}} | "
        f"{'Instagram':<{COL_WIDTHS['Instagram']}} | "
        f"{'Relationship':<{COL_WIDTHS['Relationship']}} | "
        f"{'Interaction Lvl':<{COL_WIDTHS['Interaction Lvl']}} | "
        f"{'Feelings Lvl':<{COL_WIDTHS['Feelings Lvl']}} | "
        f"{'Future Plan':<{COL_WIDTHS['Future Plan']}} | "
        f"Notes"
    )
    print(header)
    print("-" * (sum(COL_WIDTHS.values()) + len(COL_WIDTHS) * 3 + 5))

    for index, row_data in enumerate(all_crushes):
        formatted_row = [str(value) if value is not None else 'NULL' for value in row_data]

        relationship_status = formatted_row[6]
        if len(relationship_status) > COL_WIDTHS['Relationship']:
            relationship_status = relationship_status[:COL_WIDTHS['Relationship'] - 3] + '...'

        # Truncate Future Plan
        future_plan = formatted_row[9]
        if len(future_plan) > COL_WIDTHS['Future Plan']:
            future_plan = future_plan[:COL_WIDTHS['Future Plan'] - 3] + '...'

        # Truncate Notes
        notes = formatted_row[10]
        if len(notes) > COL_WIDTHS['Notes']:
            notes = notes[:COL_WIDTHS['Notes'] - 3] + '...'


        print(
            f"{index + 1:<{COL_WIDTHS['Index']}} | "
            f"{formatted_row[0]:<{COL_WIDTHS['First Name']}} | "
            f"{formatted_row[1]:<{COL_WIDTHS['Last Name']}} | "
            f"{formatted_row[2]:<{COL_WIDTHS['Gender']}} | "
            f"{formatted_row[3]:<{COL_WIDTHS['Age']}} | "
            f"{formatted_row[4]:<{COL_WIDTHS['Phone']}} | "
            f"{formatted_row[5]:<{COL_WIDTHS['Instagram']}} | "
            f"{relationship_status:<{COL_WIDTHS['Relationship']}} | "
            f"{formatted_row[7]:<{COL_WIDTHS['Interaction Lvl']}} | "
            f"{formatted_row[8]:<{COL_WIDTHS['Feelings Lvl']}} | "
            f"{future_plan:<{COL_WIDTHS['Future Plan']}} | "         
            f"{notes}"
        )
    print("-" * (sum(COL_WIDTHS.values()) + len(COL_WIDTHS) * 3 + 5))
    return all_crushes


def view_single_crush(cursor):
    print("\n--- View Single Crush ---")
    all_crushes_data = display_crushes(cursor)

    if not all_crushes_data:
        return

    try:
        view_index_str = input("Enter the Index of the crush you want to view: ")
        view_index = int(view_index_str) - 1

        if not (0 <= view_index < len(all_crushes_data)):
            print("Invalid index selected.")
            return
    except ValueError:
        print("Invalid input. Please enter a number for the index.")
        return

    selected_crush = all_crushes_data[view_index]

    print(f"\n--- Details for {selected_crush[0]} {selected_crush[1]} ---")
    print(f"First Name:        {selected_crush[0] if selected_crush[0] is not None else 'NULL'}")
    print(f"Last Name:         {selected_crush[1] if selected_crush[1] is not None else 'NULL'}")
    print(f"Gender:            {selected_crush[2] if selected_crush[2] is not None else 'NULL'}")
    print(f"Age:               {selected_crush[3] if selected_crush[3] is not None else 'NULL'}")
    print(f"Phone Number:      {selected_crush[4] if selected_crush[4] is not None else 'NULL'}")
    print(f"Instagram ID:      {selected_crush[5] if selected_crush[5] is not None else 'NULL'}")
    print(f"Relationship Status: {selected_crush[6] if selected_crush[6] is not None else 'NULL'}")
    print(f"Interaction Level: {selected_crush[7] if selected_crush[7] is not None else 'NULL'}")
    print(f"Feelings Level:    {selected_crush[8] if selected_crush[8] is not None else 'NULL'}")
    print(f"Future Plan:       {selected_crush[9] if selected_crush[9] is not None else 'NULL'}")
    print(f"Notes:             {selected_crush[10] if selected_crush[10] is not None else 'NULL'}")
    print("---------------------------------------")


def add_new_crush(cursor, cnx):
    print("\n--- Add New Crush ---")
    print("Please enter the new crush's information (press Enter to skip a field for NULL):")

    first_name = get_text_input_or_none("First name (text, max 15 characters): ")
    last_name = get_text_input_or_none("Last name (text, max 15 characters): ")
    gender = get_gender_input_or_none("Gender ('male' or 'female', or press Enter for NULL): ")
    age = get_integer_input_or_none("Age (integer, e.g., 28): ")
    phone_number = get_text_input_or_none("Phone number (text, max 20 characters): ")
    instagram_id = get_text_input_or_none("Instagram ID (text, max 50 characters): ")
    relationship_status = get_text_input_or_none("Relationship status (text, max 50 chars): ")
    interaction_level = get_integer_input_or_none("Interaction level (integer, e.g., 1-5): ")
    feelings_level = get_integer_input_or_none("Feelings level (integer, e.g., 1-5): ")
    future_plan = get_text_input_or_none("Future plan (text, max 50 chars): ")
    notes = get_text_input_or_none("Additional notes (long text): ")

    insert_sql_query = """
                       INSERT INTO crushes (first_name, last_name, gender, age, phone_number, instagram_id, 
                                            relationship_status, interaction_level, feelings_level, 
                                            future_plan, notes) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
                       """
    record_to_insert = (
        first_name, last_name, gender, age, phone_number, instagram_id,
        relationship_status, interaction_level, feelings_level,
        future_plan, notes
    )

    cursor.execute(insert_sql_query, record_to_insert)
    cnx.commit()
    print(f"\n{cursor.rowcount} record inserted successfully into crushes table.")


def edit_existing_crush(cursor, cnx):
    print("\n--- Edit Existing Crush ---")
    all_crushes_data = display_crushes(cursor)

    if not all_crushes_data:
        return

    try:
        edit_index_str = input("Enter the Index of the crush you want to edit: ")
        edit_index = int(edit_index_str) - 1

        if not (0 <= edit_index < len(all_crushes_data)):
            print("Invalid index selected.")
            return
    except ValueError:
        print("Invalid input. Please enter a number for the index.")
        return

    selected_crush_original_data = all_crushes_data[edit_index]
    original_first_name = selected_crush_original_data[0]
    original_last_name = selected_crush_original_data[1]

    print(f"\nEditing crush: {original_first_name} {original_last_name}")
    print(
        "For each field, enter the new value. Press Enter to keep the current value. Type 'NULL' to set field to NULL.")

    current_values_map = {
        "First name": selected_crush_original_data[0], "Last name": selected_crush_original_data[1],
        "Gender": selected_crush_original_data[2], "Age": selected_crush_original_data[3],
        "Phone number": selected_crush_original_data[4], "Instagram ID": selected_crush_original_data[5],
        "Relationship status": selected_crush_original_data[6], "Interaction level": selected_crush_original_data[7],
        "Feelings level": selected_crush_original_data[8], "Future plan": selected_crush_original_data[9],
        "Notes": selected_crush_original_data[10]
    }

    updated_values = []

    new_val_str = input(f"New First name (current: {current_values_map['First name']}): ").strip()
    updated_values.append(current_values_map['First name'] if new_val_str == "" else (
        None if new_val_str.upper() == "NULL" else new_val_str))

    new_val_str = input(f"New Last name (current: {current_values_map['Last name']}): ").strip()
    updated_values.append(current_values_map['Last name'] if new_val_str == "" else (
        None if new_val_str.upper() == "NULL" else new_val_str))

    while True:
        new_val_str = input(f"New Gender (current: {current_values_map['Gender']}, 'male'/'female'): ").strip().lower()
        if new_val_str == "":
            updated_values.append(current_values_map['Gender'])
            break
        elif new_val_str == "null":
            updated_values.append(None)
            break
        elif new_val_str in ['male', 'female']:
            updated_values.append(new_val_str)
            break
        else:
            print("Invalid gender. Enter 'male', 'female', 'NULL', or press Enter to keep current.")

    new_val_str = input(f"New Age (current: {current_values_map['Age']}): ").strip()
    if new_val_str == "":
        updated_values.append(current_values_map['Age'])
    elif new_val_str.upper() == "NULL":
        updated_values.append(None)
    else:
        try:
            updated_values.append(int(new_val_str))
        except ValueError:
            print(f"Invalid age. Keeping current ({current_values_map['Age']})."); updated_values.append(
                current_values_map['Age'])

    new_val_str = input(f"New Phone number (current: {current_values_map['Phone number']}): ").strip()
    updated_values.append(current_values_map['Phone number'] if new_val_str == "" else (
        None if new_val_str.upper() == "NULL" else new_val_str))

    new_val_str = input(f"New Instagram ID (current: {current_values_map['Instagram ID']}): ").strip()
    updated_values.append(current_values_map['Instagram ID'] if new_val_str == "" else (
        None if new_val_str.upper() == "NULL" else new_val_str))


    new_val_str = input(f"New Relationship status (current: {current_values_map['Relationship status']}): ").strip()
    updated_values.append(current_values_map['Relationship status'] if new_val_str == "" else (
        None if new_val_str.upper() == "NULL" else new_val_str))

    new_val_str = input(f"New Interaction level (current: {current_values_map['Interaction level']}): ").strip()
    if new_val_str == "":
        updated_values.append(current_values_map['Interaction level'])
    elif new_val_str.upper() == "NULL":
        updated_values.append(None)
    else:
        try:
            updated_values.append(int(new_val_str))
        except ValueError:
            print(
                f"Invalid interaction level. Keeping current ({current_values_map['Interaction level']})."); updated_values.append(
                current_values_map['Interaction level'])

    new_val_str = input(f"New Feelings level (current: {current_values_map['Feelings level']}): ").strip()
    if new_val_str == "":
        updated_values.append(current_values_map['Feelings level'])
    elif new_val_str.upper() == "NULL":
        updated_values.append(None)
    else:
        try:
            updated_values.append(int(new_val_str))
        except ValueError:
            print(
                f"Invalid feelings level. Keeping current ({current_values_map['Feelings level']})."); updated_values.append(
                current_values_map['Feelings level'])

    new_val_str = input(f"New Future plan (current: {current_values_map['Future plan']}): ").strip()
    updated_values.append(current_values_map['Future plan'] if new_val_str == "" else (
        None if new_val_str.upper() == "NULL" else new_val_str))

    new_val_str = input(f"New Notes (current: {current_values_map['Notes']}): ").strip()
    updated_values.append(
        current_values_map['Notes'] if new_val_str == "" else (None if new_val_str.upper() == "NULL" else new_val_str))

    update_sql_query = """
                       UPDATE crushes 
                       SET first_name          = %s, 
                           last_name           = %s, 
                           gender              = %s, 
                           age                 = %s, 
                           phone_number        = %s, 
                           instagram_id        = %s, 
                           relationship_status = %s, 
                           interaction_level   = %s, 
                           feelings_level      = %s, 
                           future_plan         = %s, 
                           notes               = %s
                       WHERE first_name = %s 
                         AND last_name = %s 
                       """

    query_params = tuple(updated_values) + (original_first_name, original_last_name)

    cursor.execute(update_sql_query, query_params)
    cnx.commit()

    if cursor.rowcount > 0:
        print(f"\nRecord for {original_first_name} {original_last_name} updated successfully.")
    else:
        print(f"\nNo record found for {original_first_name} {original_last_name} or no changes made.")


def delete_crush(cursor, cnx):
    print("\n--- Delete Existing Crush ---")
    all_crushes_data = display_crushes(cursor)

    if not all_crushes_data:
        return

    try:
        delete_index_str = input("Enter the Index of the crush you want to DELETE: ")
        delete_index = int(delete_index_str) - 1

        if not (0 <= delete_index < len(all_crushes_data)):
            print("Invalid index selected.")
            return
    except ValueError:
        print("Invalid input. Please enter a number for the index.")
        return

    crush_to_delete = all_crushes_data[delete_index]
    first_name = crush_to_delete[0]
    last_name = crush_to_delete[1]

    confirmation = input(f"Are you sure you want to delete {first_name} {last_name}? (yes/no): ").strip().lower()

    if confirmation == 'yes':
        delete_sql_query = "DELETE FROM crushes WHERE first_name = %s AND last_name = %s"
        cursor.execute(delete_sql_query, (first_name, last_name))
        cnx.commit()
        if cursor.rowcount > 0:
            print(f"Crush '{first_name} {last_name}' deleted successfully.")
        else:
            print(f"Could not delete crush '{first_name} {last_name}'.")
    else:
        print("Deletion cancelled.")


def main_application():
    db_connection = None
    db_cursor = None
    try:
        db_connection = mysql.connector.connect(
            host="localhost",
            user="alirezza",
            password="",
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
                print("Exiting application.")
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 6.")

    except mysql.connector.Error as db_error:
        print(f"Database error: {db_error}")
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