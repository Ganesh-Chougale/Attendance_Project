Annotations in java is a label of a class, method, field that tells the metadata(information) to the compiler, runtime enivornment or frameworkds.  
### `@Entity`  
marks the class as JPA Entity = `Database table`.  
### `@Override`  
to tell the enviroment that we are intentionally overriding a method which is derived from superclass. (if we do mistake between name, parameters, return type, by help of this annotation we get compiletime error).  

### `@Id`  
Marks `id` as the primary key.

### `@Component`  
tell that class is Spring-managed bean.  
**When to Use?** : Use `@Component` when your class doesn’t fit into a specific role like service, repository, or controller but still needs to be managed by Spring.  

### `@Bean`  
unlike @Component (which is manged by spring), `@Bean` is managed by developer to write custom logic under `@Configuration` class. this gives you more control over bean creation.  
### `@MappedSuperclass`  
This annotation tells JPA that this class is not an entity itself and won't be mapped to a separate table. Instead, its properties will be inherited and mapped to the tables of its subclasses (your actual entities like User, Class, etc.).  

### `@Getter` and `@Setter` (Lombok)  
These annotations from Lombok automatically generate the getter and setter methods for `id`, `createdAt`, and `updatedAt`, reducing boilerplate code.

### `@GeneratedValue(strategy = GenerationType.IDENTITY)`
Configures the primary key to be auto-incremented by the database. `IDENTITY` is suitable for MySQL.  

### `@Column(name = "created_at", nullable = false, updatable = false)`  
Maps this field to a database column named `created_at`. `nullable = false` ensures it's always present, and u`pdatable = false` means its value won't be changed on subsequent updates.  

### `@PrePersist` and `onCreate()` method  
- `@PrePersist` is a JPA lifecycle callback. The `onCreate()` method will be executed before a new entity is persisted (inserted) into the database.

### `@PreUpdate` and `onUpdate()` method  
- `@PreUpdate` is another JPA lifecycle callback. The `onUpdate()` method will be executed before an existing entity is updated in the database.