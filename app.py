from flask import Flask, request, jsonify
import mysql.connector
import database_logic 

app = Flask(__name__)

@app.route('/crushes', methods=['POST'])
def api_create_crush():
    cnx = None
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        
        new_crush_id = database_logic.create_new_crush(cursor, cnx, data)
        created_crush = database_logic.get_crush_details(cursor, new_crush_id) # Fetch the created crush to return it
        
        return jsonify(created_crush), 201
        
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except mysql.connector.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx and cnx.is_connected():
            cnx.close()

@app.route('/crushes', methods=['GET'])
def api_get_all_crushes():
    cnx = None
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crushes = database_logic.list_all_crushes(cursor)
        return jsonify(crushes), 200
    except mysql.connector.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx and cnx.is_connected():
            cnx.close()

@app.route('/crushes/<int:crush_id>', methods=['GET'])
def api_get_crush(crush_id):
    cnx = None
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        crush = database_logic.get_crush_details(cursor, crush_id)
        return jsonify(crush), 200
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mysql.connector.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx and cnx.is_connected():
            cnx.close()

@app.route('/crushes/<int:crush_id>', methods=['PUT'])
def api_update_crush(crush_id):
    cnx = None
    cursor = None
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        data = request.get_json()
        if not data:
            return jsonify({"error": "No update data provided"}), 400

        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        
        affected_rows = database_logic.update_existing_crush(cursor, cnx, crush_id, data)
        if affected_rows > 0:
            updated_crush = database_logic.get_crush_details(cursor, crush_id)
            return jsonify(updated_crush), 200
        else:
            # This case might be covered by NotFoundError if get_crush_details in update_existing_crush fails
            # or if data didn't lead to an actual update (e.g. same values)
            return jsonify({"message": "Crush found but no changes made or data invalid"}), 200 
            
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except mysql.connector.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx and cnx.is_connected():
            cnx.close()

@app.route('/crushes/<int:crush_id>', methods=['DELETE'])
def api_delete_crush(crush_id):
    cnx = None
    cursor = None
    try:
        cnx = database_logic.get_db_connection()
        cursor = cnx.cursor()
        
        affected_rows = database_logic.delete_existing_crush(cursor, cnx, crush_id)
        if affected_rows > 0:
            return jsonify({"message": f"Crush with ID {crush_id} deleted successfully."}), 200
        else:
            # This case is now covered by NotFoundError raised in delete_existing_crush
            return jsonify({"error": f"Crush with ID {crush_id} not found or already deleted."}), 404 # Should be caught by NotFoundError
            
    except database_logic.NotFoundError as nfe:
        return jsonify({"error": str(nfe)}), 404
    except mysql.connector.Error as dbe:
        return jsonify({"error": "Database error", "details": str(dbe)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if cnx and cnx.is_connected():
            cnx.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
