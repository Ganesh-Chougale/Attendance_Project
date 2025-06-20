### **II. User Profile Endpoints (`UserController`)**

These endpoints are for authenticated users to manage their *own* profiles.

**Setup for these requests:** In Postman, go to the "Authorization" tab for each request, select "Type: Bearer Token", and paste the JWT you obtained from the login response into the "Token" field.

**1. Get User Profile (GET)**

* **URL:** `http://localhost:8080/api/user/profile`
* **Method:** `GET`
* **Headers:**
    * `Authorization`: `Bearer <YOUR_JWT_TOKEN>`
* **Expected Response:** `200 OK` with a `UserProfileDto` (or `UserDto` depending on the mapper) representing the logged-in user's profile.
    ```json
    {
        "id": 1,
        "username": "testuser",
        "firstName": "Test",
        "lastName": "User",
        "email": "test@example.com",
        "role": "STUDENT",
        "enabled": true
    }
    ```
* **Test Cases:**
    * Successful retrieval of profile for a logged-in user (any role).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).
    * Attempt with invalid/expired JWT (should get `401 Unauthorized`).

**2. Update User Profile (PUT)**

* **URL:** `http://localhost:8080/api/user/profile`
* **Method:** `PUT`
* **Headers:**
    * `Content-Type`: `application/json`
    * `Authorization`: `Bearer <YOUR_JWT_TOKEN>`
* **Body (raw JSON):**
    ```json
    {
        "firstName": "Updated",
        "lastName": "User",
        "email": "updated_test@example.com"
        // Do NOT include username or role here, as they are not updatable via this endpoint
    }
    ```
* **Expected Response:** `200 OK` with the updated `UserDto` (or `UserProfileDto`).
* **Test Cases:**
    * Successful update of first name, last name, email.
    * Attempt to change email to one already taken by another user (should get `400 Bad Request`).
    * Attempt to update `username` or `role` (these fields are ignored by the service, so the response will still be 200 OK, but the fields won't change).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).

---

### **III. Admin Endpoints (`AdminController`)**

These endpoints are *only* accessible to users with the `ADMIN` role. You'll need to **register and login as an ADMIN user** to test these.

**Setup for these requests:**
1.  Register an admin user first (if you haven't):
    ```json
    {
        "username": "adminuser",
        "password": "adminpassword",
        "firstName": "Admin",
        "lastName": "User",
        "email": "admin@example.com",
        "role": "ADMIN"
    }
    ```
2.  Login with these admin credentials to get a new JWT.
3.  Use this **ADMIN JWT** as the Bearer Token for all `AdminController` requests.

**1. Create User (POST)**

* **URL:** `http://localhost:8080/api/admin/users`
* **Method:** `POST`
* **Headers:**
    * `Content-Type`: `application/json`
    * `Authorization`: `Bearer <YOUR_ADMIN_JWT_TOKEN>`
* **Body (raw JSON):**
    ```json
    {
        "username": "newteacher",
        "password": "teacherpass",
        "firstName": "New",
        "lastName": "Teacher",
        "email": "newteacher@example.com",
        "role": "TEACHER" // Can be STUDENT, TEACHER, or ADMIN
    }
    ```
* **Expected Response:** `200 OK` with the `UserDto` of the newly created user.
* **Test Cases:**
    * Successful creation of a new user (any role).
    * Creation with existing username (should get `400 Bad Request`).
    * Creation with existing email (should get `400 Bad Request`).
    * Attempt by a `STUDENT` or `TEACHER` user (should get `403 Forbidden`).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).

**2. Get All Users (GET)**

* **URL:** `http://localhost:8080/api/admin/users`
* **Method:** `GET`
* **Headers:**
    * `Authorization`: `Bearer <YOUR_ADMIN_JWT_TOKEN>`
* **Query Parameters (Optional):**
    * `role`: `STUDENT`, `TEACHER`, or `ADMIN` (e.g., `http://localhost:8080/api/admin/users?role=STUDENT`)
* **Expected Response:** `200 OK` with a list of `UserDto` objects.
* **Test Cases:**
    * Retrieve all users.
    * Retrieve users by specific role.
    * Attempt by a `STUDENT` or `TEACHER` user (should get `403 Forbidden`).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).

**3. Get User by ID (GET)**

* **URL:** `http://localhost:8080/api/admin/users/{userId}` (replace `{userId}` with an actual user ID, e.g., `http://localhost:8080/api/admin/users/1`)
* **Method:** `GET`
* **Headers:**
    * `Authorization`: `Bearer <YOUR_ADMIN_JWT_TOKEN>`
* **Expected Response:** `200 OK` with a `UserDto` for the specified user.
* **Test Cases:**
    * Successful retrieval of an existing user.
    * Attempt to get a non-existent user ID (should get `400 Bad Request` with "User not found").
    * Attempt by a `STUDENT` or `TEACHER` user (should get `403 Forbidden`).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).

**4. Update User by ID (PUT)**

* **URL:** `http://localhost:8080/api/admin/users/{userId}` (replace `{userId}` with an actual user ID)
* **Method:** `PUT`
* **Headers:**
    * `Content-Type`: `application/json`
    * `Authorization`: `Bearer <YOUR_ADMIN_JWT_TOKEN>`
* **Body (raw JSON):**
    ```json
    {
        "firstName": "AdminChanged",
        "email": "changed_email@example.com",
        "role": "TEACHER", // Can change role
        "enabled": false // Can enable/disable user
    }
    ```
    * **Note:** You can update any of `firstName`, `lastName`, `email`, `role`, or `enabled`.
* **Expected Response:** `200 OK` with the `UserDto` of the updated user.
* **Test Cases:**
    * Successful update of various fields, including role and enabled status.
    * Attempt to change email to one already taken by another user (should get `400 Bad Request`).
    * Attempt to update a non-existent user ID (should get `400 Bad Request`).
    * Attempt by a `STUDENT` or `TEACHER` user (should get `403 Forbidden`).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).

**5. Delete User (Soft Delete) (DELETE)**

* **URL:** `http://localhost:8080/api/admin/users/{userId}` (replace `{userId}` with an actual user ID)
* **Method:** `DELETE`
* **Headers:**
    * `Authorization`: `Bearer <YOUR_ADMIN_JWT_TOKEN>`
* **Expected Response:** `204 No Content` (meaning the request was successful but there's no content to return).
* **Test Cases:**
    * Successful soft delete of an existing user (check `GET /api/admin/users/{userId}` afterwards to see `enabled: false`).
    * Attempt to delete a non-existent user ID (should get `400 Bad Request`).
    * Attempt by a `STUDENT` or `TEACHER` user (should get `403 Forbidden`).
    * Attempt without `Authorization` header (should get `401 Unauthorized`).

---

### **IV. Health Check Endpoint (Actuator)**

* **URL:** `http://localhost:8080/actuator/health`
* **Method:** `GET`
* **Headers:** None required.
* **Expected Response:** `200 OK` with details about application health (should show `status: UP` and database details).
    ```json
    {
        "status": "UP",
        "components": {
            "db": {
                "status": "UP",
                "details": {
                    "database": "MySQL",
                    "validationQuery": "isValid()"
                }
            },
            "diskSpace": {
                "status": "UP",
                "details": {
                    "total": 510427842560,
                    "free": 331776856064,
                    "threshold": 10485760
                }
            },
            "ping": {
                "status": "UP"
            }
        }
    }
    ```

---

**Tips for Postman:**

* **Create a Collection:** Organize your requests into a Postman collection (e.g., "Attendance Backend API"). This makes it easy to run requests, manage environments, and share.
* **Environments:** Use Postman environments to store variables like `baseUrl` (`http://localhost:8080`) and `jwtToken`. This allows you to quickly switch between development, testing, and production environments without changing every URL or token.
* **Pre-request Scripts (Advanced):** For a more automated workflow, you could use Postman's pre-request scripts to automatically extract the JWT from the login response and set it as an environment variable for subsequent requests. This is very useful for large APIs.
    * **Login Request Tests (under Tests tab):**
        ```javascript
        var jsonData = pm.response.json();
        pm.environment.set("jwt_token", jsonData.token);
        ```
    * **Protected Request Pre-request Script:**
        ```javascript
        pm.request.headers.add({
            key: 'Authorization',
            value: 'Bearer ' + pm.environment.get("jwt_token")
        });
        ```
* **Error Messages:** Pay close attention to the HTTP status codes and the JSON error messages in the response body. They provide valuable debugging information.