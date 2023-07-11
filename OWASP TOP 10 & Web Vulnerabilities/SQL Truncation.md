*SQL Truncation* is an attack technique in which an attacker attempts to *truncate* or *cut* off an SQL query to perform malicious actions on a *database*.

A common example of this type of attack is when a web application has an input field that limits the length of data, such as email, and does not properly validate the input data.

Let's assume for example a page which has a registration field to create a new user. In this registration field, the user must provide an email address and the password of the user in question that he wants to create. Now, in order to insert this data into the database, let's suppose that the field corresponding to the email address entered by the user is limited to *17 characters* in the database.

Assuming that for example the user '*admin\@admin.com*' already exists in the database, at first it would not be possible to register this same user, because the SQL query that would be applied from behind would consider it as a duplicate entry. However, given that the email '*admin\@admin.com*' has a total of *15 characters* and we have not yet reached the limit, an attacker could try to register the user '*admin\@admin.com a*', or in other words: '*admin\@admin.com\[space]\[space]a*'.

This new string that we have represented for the email, in this case has a total of *18 characters*. At first the mail is different from the mail already existing in the database (*admin\@admin.com*), however, due to its limitation in *17 characters*, after passing the first filter and proceed to its insertion in the database, the total length of the string is shortened to 17 characters, resulting in the string '*admin\@admin.com*', or in other words: '*admin\@admin.com\[space]\[space]*'.

Now, what happens with the spaces, since they do not represent "information of value", so to speak, what will happen is that they will be *truncated*. What we mean by *truncating the spaces* at the end of the string is their automatic elimination. In this way, the resulting final string would remain '*admin\@admin.com*', and after its insertion in the database, the password would be changed to the one specified during the registration phase for our supposed "*new user*".

This attack will work for cases where the web application does not properly validate the input data and cuts or truncates the SQL query instead of displaying an error message. Consequently, the attacker can exploit this weakness to perform malicious actions on the database, such as modifying or deleting data, accessing sensitive information, or taking control of a user account.

To prevent the SQL truncation attack, it is important to properly validate all user input data used in SQL queries. Validation should include both the length and format of the input data.

# Example