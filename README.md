# Student-Parent Location Monitoring System

Ang sistema na ito ay isang real-time location tracking application para sa mga estudyante at kanilang mga magulang. Gumagamit ito ng Folium at Leaflet para sa mapping at Flask para sa web framework.

## Features

- **User Authentication**: Signup at login system para sa mga estudyante at magulang
- **Parent-Student Connection**: Sistema ng pag-connect ng mga accounts ng magulang at estudyante
- **Real-time Location Tracking**: Maaaring i-share ng estudyante ang kanilang location sa real-time
- **Secure Monitoring**: Ang magulang ay makikita lamang ang location ng kanilang naka-connect na anak
- **Location History**: History ng mga recent locations para sa mas madaling pag-track

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Real-time Communication**: Socket.IO
- **Mapping**: Folium/Leaflet
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Authentication**: Flask-Login

## Setup Instructions

1. I-install ang mga dependencies:
   ```
   pip install -r requirements.txt
   ```

2. I-set ang environment variables (optional):
   ```
   export SECRET_KEY=your_secret_key
   ```

3. I-run ang application:
   ```
   python app.py
   ```

4. Buksan ang browser at pumunta sa `http://127.0.0.1:5000`

## Usage Guide

### Para sa mga Estudyante:

1. Mag-sign up gamit ang "Student" account type
2. Sa dashboard, i-click ang "Connect" para i-link ang iyong account sa account ng iyong magulang
3. Pagkatapos ma-accept ng magulang ang connection request, maaari mo nang gamitin ang "Start Tracking" button para magbigay ng real-time location updates

### Para sa mga Magulang:

1. Mag-sign up gamit ang "Parent" account type
2. Connect sa account ng iyong anak, o kaya'y tanggapin ang connection request mula sa kanya
3. Sa dashboard, makikita mo ang real-time location ng iyong anak kapag nag-start sila ng tracking

## Security Features

- Secure password hashing gamit ang Werkzeug
- User authentication at session management gamit ang Flask-Login
- Relationship verification - tanging ang parent-student connections lang ang maaaring mag-share ng location data

## Contributors

- Your Name - Initial development

## License

This project is licensed under the MIT License - see the LICENSE file for details. 