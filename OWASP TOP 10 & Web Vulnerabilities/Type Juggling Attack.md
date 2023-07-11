A **Type Juggling** attack is a technique used in programming *to manipulate the data type* of a variable in order to trick a program into doing something it should not.

Most programming languages use data types to classify the information stored in a variable, such as integers, strings, floats, booleans, and so on. Programs use these data types to perform mathematical operations, comparisons and other specific tasks. However, attackers can exploit vulnerabilities in programs that do not properly validate the data types provided to them.

In a Type Juggling attack, an attacker manipulates program input data to change the data type of a variable. For example, the attacker might provide a string that "looks like" an integer, but in reality is not. If the program does not properly validate the variable's data type, it could attempt to perform mathematical operations on that variable and get unexpected results.

A common example of how a Type Juggling attack can be used to circumvent authentication is in a system that uses string comparisons to verify user passwords. Instead of providing a valid password, the attacker could provide a string that looks like a valid password, but actually is not.

For example, in *PHP*, a string that starts with a number is automatically converted to a number if it is used in a numeric comparison. Therefore, if the attacker provides a string that begins with the number *zero (0)*, such as "*00123*", the program will convert it to the integer *123*.

If the password stored in the system is also stored as an integer (instead of as a string), the comparison of the attacker's password with the stored password could be successful, allowing the attacker to bypass authentication and gain unauthorized access to the system.