# Crush Manager API

A simple API to manage a list of crushes, built with Flask and MariaDB/MySQL.

## Prerequisites

* Python (3.7+ recommended)
* MariaDB (or MySQL) server running
* `pip` for installing Python packages

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-name>
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Database Setup:**
    * Ensure your MariaDB/MySQL server is running.
    * Create a database named `learningdb`.
    * Connect to your database and create the `crushes` table with the following schema (or adapt as needed):
        ```sql
        USE learningdb;

        CREATE TABLE IF NOT EXISTS crushes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(15) NOT NULL, -- Made first_name NOT NULL as an example
            last_name VARCHAR(15),
            gender ENUM('male', 'female'),
            acquaintance_date DATE, -- Should be after gender physically in DB if you ran the ALTER
            age INT,
            phone_number VARCHAR(20),
            instagram_id VARCHAR(50),
            relationship_status VARCHAR(50),
            interaction_level INT,
            feelings_level INT,
            future_plan VARCHAR(50),
            notes TEXT
        );
        -- Ensure the physical order of acquaintance_date is after gender if that was intended
        -- The logical order in SELECT statements in database_logic.py is what matters for API output structure
        ```
    * Ensure the user `alirezza` exists and has permissions to access `learningdb` from `localhost` with an empty password (as configured in `database_logic.py`). You might need to create this user and grant permissions:
        ```sql
        -- Example:
        -- CREATE USER 'alirezza'@'localhost' IDENTIFIED BY ''; -- For empty password
        -- GRANT ALL PRIVILEGES ON learningdb.* TO 'alirezza'@'localhost';
        -- FLUSH PRIVILEGES;
        ```

## Running the Application

To start the Flask development server:

```bash
python app.py
