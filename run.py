from app import app, db, socketio

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    print("Student-Parent Monitoring System is running!")
    print("Access the application at: http://127.0.0.1:5000")
    socketio.run(app, debug=True, host='0.0.0.0') 