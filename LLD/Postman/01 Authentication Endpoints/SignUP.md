### **Authentication Endpoints (`AuthController`)**

**1. Register User (POST)**

* **URL:** `http://localhost:8080/api/auth/register`
* **Method:** `POST`
* **Headers:**
    * `Content-Type`: `application/json`
* **Body (raw JSON):**
    ```json
    {
        "username": "ganesh",
        "password": "password123",
        "firstName": "Ganesh",
        "lastName": "Chougale",
        "email": "gnesh@gmail.com",
        "role": "STUDENT"
    }
    ```
    * **Note:** You can register users with `STUDENT`, `TEACHER`, or `ADMIN` roles. If `role` is omitted, it defaults to `STUDENT` in `AuthService`.
* **Response:** `200 OK` with a JSON body containing a `token`.
    ```json
        {
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJnYW5lc2giLCJpYXQiOjE3NTAyNjAzNDksImV4cCI6MTc1MDM0Njc0OX0.LPEGRDd0YtzSs_ZywWwpdg_1IjJxHmGu4JJCC32o4z8"
        }
    ```
* **Test Cases:**
    * Successful registration (new username, new email).
    * Registration with existing username (should get `400 Bad Request`).
    * Registration with existing email (should get `400 Bad Request`).
    * Registration with missing required fields (e.g., `username`, `password`, `email`) (should get `400 Bad Request` due to `@NotBlank` or `@NotNull` annotations).

**2. Login User (POST)**

* **URL:** `http://localhost:8080/api/auth/login`
* **Method:** `POST`
* **Headers:**
    * `Content-Type`: `application/json`
* **Body (raw JSON):**
    ```json
    {
        "username": "ganesh",
        "password": "password123"
    }
    ```
    * Use credentials of a registered user.
* **Expected Response:** `200 OK` with a JSON body containing a `token`.
    ```json
    {
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJnYW5lc2giLCJpYXQiOjE3NTAyNjA0NDAsImV4cCI6MTc1MDM0Njg0MH0.o9yLMeqG-MAivH2RW1cMHTbXn40k8Qv6ll9nS7k30cg"
    }
    ```
* **Action:** **Copy this token.** You will use it for all subsequent authenticated requests.
* **Test Cases:**
    * Successful login.
    * Login with incorrect password (should get `401 Unauthorized`).
    * Login with non-existent username (should get `401 Unauthorized`).