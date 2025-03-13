from app import app, db
import pyodbc
import urllib.parse

def run_migration():
    with app.app_context():
        # Kuhanin ang connection string mula sa app config
        params = urllib.parse.quote_plus("Driver={ODBC Driver 17 for SQL Server};"
                                    "Server=studenttracker.mssql.somee.com;"
                                    "Database=studenttracker;"
                                    "UID=zyber20_SQLLogin_1;"
                                    "PWD=yqvmnkmzs8;"
                                    "TrustServerCertificate=yes")
        
        connection_string = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER=studenttracker.mssql.somee.com;DATABASE=studenttracker;UID=zyber20_SQLLogin_1;PWD=yqvmnkmzs8;TrustServerCertificate=yes"
        
        # Connect to the database
        conn = pyodbc.connect(connection_string)
        cursor = conn.cursor()
        
        try:
            # Check if column exists first
            cursor.execute("""
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'full_name'
            """)
            column_exists = cursor.fetchone()[0] > 0
            
            if not column_exists:
                print("Adding full_name column to users table...")
                # Add the full_name column to the users table
                cursor.execute("""
                    ALTER TABLE users 
                    ADD full_name NVARCHAR(150) NULL
                """)
                conn.commit()
                print("Migration completed successfully!")
            else:
                print("Column full_name already exists in users table. No changes needed.")
                
        except Exception as e:
            print(f"Error during migration: {e}")
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    run_migration() 