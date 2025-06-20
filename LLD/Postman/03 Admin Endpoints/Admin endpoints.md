### **Admin Endpoints (`AdminController`)**

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
* **Authorization:**
    * `Bearer Token`: `Bearer <YOUR_JWT_TOKEN>`
* **Body (raw JSON):**
    ```json
    {
        "username": "kabir",
        "password": "teacherpass",
        "firstName": "Kabir",
        "lastName": "Kharade",
        "email": "Kabir@example.com",
        "role": "TEACHER"
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