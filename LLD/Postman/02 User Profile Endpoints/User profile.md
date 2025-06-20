### **User Profile Endpoints (`UserController`)**

These endpoints are for authenticated users to manage their *own* profiles.

**Setup for these requests:** In Postman, go to the "Authorization" tab for each request, select "Type: Bearer Token", and paste the JWT you obtained from the login response into the "Token" field.

**1. Get User Profile (GET)**

* **URL:** `http://localhost:8080/api/users/profile`
* **Method:** `GET`
* **Authorization:**
    * `Bearer Token`: `Bearer <YOUR_JWT_TOKEN>`
* **Expected Response:** `200 OK` with a `UserProfileDto` (or `UserDto` depending on the mapper) representing the logged-in user's profile.
    ```json
    {
        "username": "ganesh",
        "firstName": "Ganesh",
        "lastName": "Chougale",
        "email": "gnesh@gmail.com",
        "role": "STUDENT",
        "enabled": true
    }
    ```
* **Test Cases:**
    * Successful retrieval of profile for a logged-in user (any role).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).
    * Attempt with invalid/expired JWT (should get `401 Unauthorized`).

**2. Update User Profile (PUT)**

* **URL:** `http://localhost:8080/api/users/profile`
* **Method:** `PUT`
* **Authorization:**
    * `Bearer Token`: `Bearer <YOUR_JWT_TOKEN>`
* **Body (raw JSON):**
    ```json
    {
        "username": "ganesh",
        "firstName": "Ganesh",
        "lastName": "Almighty",
        "email": "g@gmail.com"
        // Do NOT include username or role here, as they are not updatable via this endpoint
    }
    ```
* **Expected Response:** `200 OK` with the updated `UserDto` (or `UserProfileDto`).
* **Test Cases:**
    * Successful update of first name, last name, email.
    * Attempt to change email to one already taken by another user (should get `400 Bad Request`).
    * Attempt to update `username` or `role` (these fields are ignored by the service, so the response will still be 200 OK, but the fields won't change).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).
