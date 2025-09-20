"""
API Testing Examples for StudIQ Authentication and User Management

This file contains example requests to test the new authentication middleware
and user management APIs.

Make sure to run the Django server first: python manage.py runserver
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000/api"  # Adjust if your API base URL is different

class StudIQAPITester:
    def __init__(self):
        self.session = requests.Session()
        self.access_token = None
        
    def signup(self, username, email, mobile, role="user"):
        """Test user signup"""
        url = f"{BASE_URL}/signup/"
        data = {
            "username": username,
            "email": email,
            "mobile": mobile,
            "role": role
        }
        response = self.session.post(url, json=data)
        print(f"Signup Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()
    
    def verify_otp(self, mobile, otp):
        """Test OTP verification"""
        url = f"{BASE_URL}/verify_otp/"
        data = {
            "mobile": mobile,
            "otp": otp
        }
        response = self.session.post(url, json=data)
        print(f"Verify OTP Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()
    
    def login(self, mobile):
        """Test user login"""
        url = f"{BASE_URL}/login/"
        data = {
            "mobile": mobile
        }
        response = self.session.post(url, json=data)
        print(f"Login Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()
    
    def verify_login_otp(self, mobile, otp):
        """Test login OTP verification"""
        url = f"{BASE_URL}/verify_login_otp/"
        data = {
            "mobile": mobile,
            "otp": otp
        }
        response = self.session.post(url, json=data)
        print(f"Verify Login OTP Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        
        # Store cookies for authenticated requests
        if response.status_code == 200:
            print("Login successful! Cookies stored for future requests.")
        
        return response.json()
    
    def get_current_user(self):
        """Test getting current user information"""
        url = f"{BASE_URL}/me/"
        response = self.session.get(url)
        print(f"Get Current User Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()
    
    def get_all_users(self):
        """Test getting all users (role-based access)"""
        url = f"{BASE_URL}/users/"
        response = self.session.get(url)
        print(f"Get All Users Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()
    
    def update_current_user(self, update_data):
        """Test updating current user information"""
        url = f"{BASE_URL}/me/update/"
        response = self.session.put(url, json=update_data)
        print(f"Update Current User Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()
    
    def logout(self):
        """Test user logout"""
        url = f"{BASE_URL}/logout/"
        response = self.session.post(url)
        print(f"Logout Response: {response.status_code}")
        print(f"Response Data: {response.json()}")
        return response.json()


def test_complete_flow():
    """Test the complete authentication and user management flow"""
    tester = StudIQAPITester()
    
    print("=== Testing Complete Authentication Flow ===\n")
    
    # 1. Test Signup
    print("1. Testing Signup...")
    signup_response = tester.signup(
        username="testuser123",
        email="test@example.com",
        mobile="9876543210",
        role="user"
    )
    
    if signup_response.get('user_id'):
        # Use the OTP from response (in production, this would be sent via SMS)
        otp = signup_response.get('otp')
        mobile = signup_response.get('mobile')
        
        print(f"\n2. Testing OTP Verification with OTP: {otp}")
        tester.verify_otp(mobile, otp)
        
        print(f"\n3. Testing Login...")
        login_response = tester.login(mobile)
        
        # In a real scenario, you'd get the OTP from SMS
        # For testing, you can check the console output for the OTP
        print("\nNote: Check the Django console for the login OTP")
        print("Enter the OTP manually to continue testing...")
        
        # Uncomment and modify the following lines to continue testing:
        # login_otp = "123456"  # Replace with actual OTP from console
        # tester.verify_login_otp(mobile, login_otp)
        # 
        # print("\n4. Testing Get Current User...")
        # tester.get_current_user()
        # 
        # print("\n5. Testing Get All Users...")
        # tester.get_all_users()
        # 
        # print("\n6. Testing Update Current User...")
        # tester.update_current_user({"age": 25, "bio": "Updated bio"})
        # 
        # print("\n7. Testing Logout...")
        # tester.logout()


def test_admin_flow():
    """Test admin user flow"""
    tester = StudIQAPITester()
    
    print("=== Testing Admin User Flow ===\n")
    
    # Create admin user
    print("1. Creating Admin User...")
    signup_response = tester.signup(
        username="admin123",
        email="admin@example.com",
        mobile="9876543211",
        role="admin"
    )
    
    # Continue with verification and login...
    # (Similar to test_complete_flow but with admin role)


def test_agent_flow():
    """Test agent user flow"""
    tester = StudIQAPITester()
    
    print("=== Testing Agent User Flow ===\n")
    
    # Create agent user
    print("1. Creating Agent User...")
    signup_response = tester.signup(
        username="agent123",
        email="agent@example.com",
        mobile="9876543212",
        role="agent"
    )
    
    # Continue with verification and login...
    # (Similar to test_complete_flow but with agent role)


if __name__ == "__main__":
    print("StudIQ API Testing Script")
    print("=" * 50)
    
    # Run the complete flow test
    test_complete_flow()
    
    print("\n" + "=" * 50)
    print("Testing completed!")
    print("\nTo test different roles:")
    print("1. Uncomment test_admin_flow() to test admin functionality")
    print("2. Uncomment test_agent_flow() to test agent functionality")
    print("\nRole-based access:")
    print("- Admin: Can see all users")
    print("- Agent: Can see only users and owners")
    print("- User/Owner: Cannot access user list")
