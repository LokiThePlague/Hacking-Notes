**CSS Injections (CSSI)** are a type of web vulnerability that allows an attacker to inject malicious CSS code into a web page. This occurs when a web application relies on untrusted user input and uses it directly in its CSS code, without performing proper validation.

The injected malicious CSS code can alter the style and layout of the page, allowing attackers to perform actions such as *phishing* or *stealing sensitive information*.

CSS Injections (CSSI) can be used by attackers as an attack vector to exploit [[Cross-Site Scripting (XSS)]] vulnerabilities. Imagine that a web application allows users to enter text into an input field displayed on a web page. If the application developer does not properly validate and filter the text entered by the user, an attacker could inject malicious code into the input field, including JavaScript code.

If the injected CSS code is "complex enough", it can cause the web browser to interpret the code as if it were JavaScript code. This means that the malicious CSS code can be used to inject JavaScript code into the web page, which is known as a CSS-Induced JavaScript Injection (CSS-Induced JavaScript Injection).

Once the JavaScript code has been injected into the page, it can be used by the attacker to perform a Cross-Site Scripting (XSS) attack. Once at this point, the attacker may be able to inject a malicious script that steals the user's credentials or redirects them to a fake web page, among many other possible vectors.

# Example

We are going to imagine that we have an *input* that allows us to change the *color* of an *HTML object* by *CSS*, in the following example we have put the *blue* color in the input, this is the result:

```html
<style>
	p.colorful {
		color: blue
	}
</style>
```

We could try to *inject* code that could be executed by the website *escaping* the *CSS* fields:

```html
<style>
	p.colorful {
		color: blue}</style><script>alert("XSS")</script>
	}
</style>
```

Which in user input would translate as: *blue}\</style>\<script>alert("XSS")\</script>*.