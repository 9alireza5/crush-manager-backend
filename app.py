from flask import Flask, request, jsonify
import mariadb  # Changed from mysql.connector
import database_logic

app = Flask(__name__)


@app.route('/crushes', methods=['POST'])
def api_create_crush():
    # API endpoint to create a new crush.
    cnx = None
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data:  # Ensure data is not empty
            return jsonify({"error": "Request body cannot be empty"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        new_crush_id = database_logic.create_new_crush(cursor, cnx, data)
        # Fetch the created crush to return it in the response
        created_crush = database_logic.get_crush_details(cursor, new_crush_id)

        return jsonify(created_crush), 201  # 201 Created

    except ValueError as ve:  # Catches validation errors from database_logic
        return jsonify({"error": "Invalid data provided", "details": str(ve)}), 400
    except mariadb.Error as dbe:  # Changed from mysql.connector.Error
        # Log the database error for internal review (optional)
        # print(f"Database error: {dbe}")
        return jsonify({"error": "Database operation failed", "details": str(dbe)}), 500
    except Exception as e:
        # Log the unexpected error for internal review (optional)
        # print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx:  # For mariadb, is_connected() method might not be standard or necessary to check before close.
            # Closing the connection is generally safe.
            cnx.close()


@app.route('/crushes', methods=['GET'])
def api_get_all_crushes():
    # API endpoint to get all crushes.
    cnx = None
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crushes = database_logic.list_all_crushes(cursor)
        return jsonify(crushes), 200
    except mariadb.Error as dbe:  # Changed from mysql.connector.Error
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx:
            cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['GET'])
def api_get_crush(crush_id):
    # API endpoint to get a specific crush by ID.
    cnx = None
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crush = database_logic.get_crush_details(cursor, crush_id)
        return jsonify(crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:  # Changed from mysql.connector.Error
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx:
            cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['PUT'])
def api_update_crush(crush_id):
    # API endpoint to update an existing crush.
    cnx = None
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data:  # Check if data is empty
            return jsonify({"error": "No update data provided"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        # update_existing_crush will raise NotFoundError if crush_id does not exist
        # or ValueError if no valid fields are provided for update.
        affected_rows = database_logic.update_existing_crush(cursor, cnx, crush_id, data)

        if affected_rows > 0:
            updated_crush = database_logic.get_crush_details(cursor, crush_id)
            return jsonify(updated_crush), 200
        else:
            # This means the crush was found, but the data provided
            # did not result in any changes to the record (e.g., same values).
            # Fetch current details to show its state. This might raise NotFoundError
            # if the record was deleted between the update attempt and this get.
            current_crush_details = database_logic.get_crush_details(cursor, crush_id)
            return jsonify({
                "message": "Crush found but no changes were made (data may be identical to existing or no updatable fields provided).",
                "crush": current_crush_details
            }), 200

    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except ValueError as ve:  # Catches validation errors or "No valid fields provided"
        return jsonify({"error": "Invalid data for update", "details": str(ve)}), 400
    except mariadb.Error as dbe:  # Changed from mysql.connector.Error
        return jsonify({"error": "Database error during update", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred during update", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx:
            cnx.close()


@app.route('/crushes/<int:crush_id>', methods=['DELETE'])
def api_delete_crush(crush_id):
    # API endpoint to delete a crush.
    cnx = None
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()

        # delete_existing_crush will raise NotFoundError if the crush_id doesn't exist
        # or if it existed but deletion affected 0 rows (which is handled inside delete_existing_crush).
        affected_rows = database_logic.delete_existing_crush(cursor, cnx, crush_id)

        # If delete_existing_crush did not raise an error, it means deletion was successful
        # and affected_rows should be > 0 (typically 1).
        if affected_rows > 0:
            return jsonify({"message": f"Crush with ID {crush_id} deleted successfully."}), 200
        else:
            # This case should ideally not be reached if delete_existing_crush
            # correctly raises NotFoundError or another error for 0 affected rows
            # after a successful find (as modified).
            # However, as a fallback, indicate an issue. A 500 might be more appropriate.
            return jsonify({
                               "error": f"Crush with ID {crush_id} was processed but not deleted as expected (0 rows affected)."}), 500

    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mariadb.Error as dbe:  # Changed from mysql.connector.Error
        return jsonify({"error": "Database error during deletion", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred during deletion", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx:
            cnx.close()


if __name__ == '__main__':
    # Ensure to set debug=False for production environments
    app.run(debug=True, host='0.0.0.0', port=5000)
