The *Prototype Pollution* attack is an attack technique that exploits vulnerabilities in the implementation of objects in JavaScript. This attack technique is used to modify the "*prototype*" property of an object in a web application, which can allow the attacker to execute malicious code or manipulate application data.

In JavaScript, the "prototype" property is used to define the properties and methods of an object. Attackers can exploit this feature of JavaScript to modify the properties and methods of an object and take control of the application.

The Prototype Pollution attack occurs when an attacker modifies the "prototype" property of an object in a web application. This can be accomplished by manipulating data that is submitted through forms or AJAX requests, or by inserting malicious code into the application's JavaScript code.

Once the object has been manipulated, the attacker can execute malicious code in the application, manipulate application data or take control of a user's session. For example, an attacker could modify the "prototype" property of a user authentication object to allow access to an account without the need for a password.

The impact of exploiting the Prototype Pollution attack can be significant, as attackers can take control of the application or compromise user data. In addition, since the attack relies on vulnerabilities in the implementation of objects in JavaScript, it can be difficult to detect and fix.

# Example

For the realization of this example we are going to clone the [skf-labs](https://github.com/blabla1337/skf-labs) repository.

Once downloaded, access to the */skf-labs/nodeJs/Prototype-Pollution* directory and execute the following commands to start the lab:

```bash
npm install
npm start
```

This will open us a web server on port *5000* of our *localhost*.

Once inside the web we must register and log in. When we are logged in our goal now is to elevate our *privileges* to become *administrator*, for this we will send a message to the administrator through the web and we will analyze the request with **BurpSuite**.

We can try to replace the body with a *JSON*, for this we must change the *Content-Type* to *application/json* and put the body in *JSON* format:

```json
{
	"email":"loki@example.com",
	"msg":"This is a sample message!"
}
```

----
> To see if it is interpreting the *JSON* we can delete some quotation marks to see if it gives us some type of error in the interpretation.
----

If it has interpreted the JSON we can try to insert a new *\_\_proto__* field:

```json
{
	"email":"loki@example.com",
	"msg":"This is a sample message!",
	"__proto__": {
		"admin":true
	}
}
```

When defining a new *prototype*, all new objects that do not have, in this case, the *admin* parameter, will automatically be assigned *admin=true*.

In this example only administrators have that property, so *all new users* that are created will have the property *admin=true*.

This could have been avoided by checking that when applying a *merge* in the *JavaScript* source code, the *\_\_proto__* string is not included in the *merge*.