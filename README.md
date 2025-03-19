# DearTime Insurance Corporate Portal

## Overview
DearTime Insurance Corporate Portal is a web-based application designed to manage corporate insurance plans and policies for businesses. This platform allows corporations to manage employee insurance, handle policy documents, track payments, and maintain corporate profiles.

## Features
- Corporate account management
- Employee/member enrollment and management
- Insurance package configuration
- Policy document handling
- Invoice generation and payment processing
- Premium calculation and adjustments
- Automated email notification system

## Technology Stack
- **Backend**: Django (Python)
- **Database**: MySQL/SQLite
- **Frontend**: HTML, CSS, JavaScript
- **Message Queue**: Built-in messaging system for email notifications
- **Payment Integration**: SenangPay payment gateway

## Project Structure
- `CorporatePortal/` - Main Django project settings
- `Portal/` - Core application handling business logic
- `MessageQueue/` - Email notification service
- `static/` - Static files (CSS, JavaScript, images)
- `media/` - User-uploaded files
- `log/` - Application logs

## Models
The system includes several key data models:
- `CorporateUser` - Corporate user accounts
- `CorporateProfile` - Company information
- `Member` - Insurance policy holders (employees)
- `Package` - Insurance packages
- `Product` - Insurance products
- `Invoice` - Payment records
- `Order` - Purchase records

## Installation
1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Apply migrations:
   ```
   python manage.py migrate
   ```
5. Create a superuser:
   ```
   python manage.py createsuperuser
   ```
6. Run the development server:
   ```
   python manage.py runserver
   ```

## Usage
After installation, you can access:
- Admin interface: `http://localhost:8000/admin/`
- Corporate portal: `http://localhost:8000/`

## Development
To contribute to the project:
1. Set up your development environment
2. Create a new branch for your feature
3. Write tests for your changes
4. Submit a pull request