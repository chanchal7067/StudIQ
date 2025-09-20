# StudIQ Authentication & Authorization System

This document describes the authentication and authorization system implemented for the StudIQ API.

## Overview

The system includes:
1. **JWT-based authentication** using cookies
2. **Role-based authorization** middleware
3. **User management APIs** with role-based access control
4. **Current user information APIs**

## Architecture

### 1. Custom Middleware (`StudIQApi/middleware.py`)

#### JWTAuthenticationMiddleware
- Extracts JWT access tokens from HTTP cookies
- Validates tokens and sets `request.user` and `request.is_authenticated`
- Handles token expiration and invalid tokens gracefully

#### RoleBasedAuthorizationMiddleware
- Provides decorators for authentication and role-based access control
- `@require_authentication`: Ensures user is authenticated
- `@require_roles(['admin', 'agent'])`: Ensures user has specific roles

### 2. User Roles

The system supports four user roles:
- **user**: Basic user with limited access
- **owner**: Property owner with moderate access
- **agent**: Real estate agent with access to users and owners
- **admin**: Administrator with full access to all users

### 3. API Endpoints

#### Authentication Endpoints
- `POST /api/signup/` - User registration
- `POST /api/verify_otp/` - Verify signup OTP
- `POST /api/login/` - User login (sends OTP)
- `POST /api/verify_login_otp/` - Verify login OTP and set cookies
- `POST /api/logout/` - Clear authentication cookies

#### User Management Endpoints
- `GET /api/users/` - Get all users (role-based access)
- `GET /api/me/` - Get current user information
- `PUT /api/me/update/` - Update current user information

#### Legacy Endpoints
- `GET /api/get_complete_profile_view_byid/<user_id>/` - Get user by ID
- `PUT /api/get_complete_profile_view_byid/<user_id>/` - Update user by ID

## Role-Based Access Control

### GET /api/users/
- **Admin**: Can see all users (user, owner, agent, admin)
- **Agent**: Can see only users and owners
- **User/Owner**: Access denied (403 Forbidden)

### GET /api/me/
- **All authenticated users**: Can access their own information

### PUT /api/me/update/
- **All authenticated users**: Can update their own information

## Authentication Flow

1. **Signup**: User provides username, email, mobile, and role
2. **OTP Verification**: User verifies mobile number with OTP
3. **Login**: User provides mobile number, receives OTP
4. **Login OTP Verification**: User verifies OTP, receives JWT tokens in cookies
5. **Authenticated Requests**: All subsequent requests include JWT token in cookies
6. **Logout**: Clears authentication cookies

## Cookie Configuration

JWT tokens are stored in HTTP-only cookies with the following settings:
- `httponly=True`: Prevents JavaScript access (XSS protection)
- `secure=False`: Set to True in production with HTTPS
- `samesite="Strict"`: CSRF protection

## Security Features

1. **JWT Token Validation**: All tokens are validated on each request
2. **Role-Based Access**: APIs check user roles before granting access
3. **HTTP-Only Cookies**: Tokens stored securely in cookies
4. **Token Expiration**: Automatic token expiration handling
5. **OTP Verification**: Two-factor authentication for login

## Installation & Setup

1. **Add Middleware** to `settings.py`:
```python
MIDDLEWARE = [
    # ... other middleware
    'StudIQApi.middleware.JWTAuthenticationMiddleware',
    'StudIQApi.middleware.RoleBasedAuthorizationMiddleware',
    # ... other middleware
]
```

2. **Run Migrations** (if needed):
```bash
python manage.py makemigrations
python manage.py migrate
```

3. **Test the APIs** using the provided test script:
```bash
python api_test_examples.py
```

## API Usage Examples

### 1. User Signup
```python
import requests

response = requests.post('http://localhost:8000/api/signup/', json={
    "username": "testuser",
    "email": "test@example.com",
    "mobile": "9876543210",
    "role": "user"
})
```

### 2. Login and Get Current User
```python
import requests

# Create session to maintain cookies
session = requests.Session()

# Login (after OTP verification)
session.post('http://localhost:8000/api/verify_login_otp/', json={
    "mobile": "9876543210",
    "otp": "123456"
})

# Get current user (authenticated request)
response = session.get('http://localhost:8000/api/me/')
```

### 3. Get All Users (Admin/Agent only)
```python
# Must be authenticated as admin or agent
response = session.get('http://localhost:8000/api/users/')
```

## Error Handling

The system returns appropriate HTTP status codes:
- `200`: Success
- `201`: Created (signup)
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (authentication required)
- `403`: Forbidden (insufficient permissions)
- `404`: Not Found

## Testing

Use the provided `api_test_examples.py` script to test all functionality:

1. **Complete Flow Test**: Tests signup, verification, login, and user management
2. **Admin Flow Test**: Tests admin-specific functionality
3. **Agent Flow Test**: Tests agent-specific functionality

## Security Considerations

1. **Production Settings**:
   - Set `secure=True` for cookies in production
   - Use HTTPS
   - Set strong `SECRET_KEY`
   - Configure proper CORS settings

2. **Token Management**:
   - Implement token refresh mechanism
   - Consider token blacklisting for logout
   - Monitor token expiration times

3. **Rate Limiting**:
   - Implement rate limiting for OTP endpoints
   - Add brute force protection

## Troubleshooting

### Common Issues

1. **Token Validation Errors**:
   - Check if JWT settings are properly configured
   - Ensure cookies are being sent with requests

2. **Role Access Denied**:
   - Verify user role in database
   - Check role-based access logic

3. **OTP Issues**:
   - Check console output for OTP values during testing
   - Implement proper SMS service for production

### Debug Tips

1. Check Django console for OTP values during testing
2. Use browser developer tools to inspect cookies
3. Enable Django debug mode for detailed error messages
4. Check middleware order in settings.py

## Future Enhancements

1. **Token Refresh**: Implement automatic token refresh
2. **Password Authentication**: Add password-based login option
3. **Social Login**: Integrate OAuth providers
4. **Audit Logging**: Track user actions and access
5. **API Rate Limiting**: Implement request rate limiting
6. **Email Verification**: Add email verification flow
