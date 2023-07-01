A **Padding Oracle Attack** is a type of attack against encrypted data that allows the attacker to *decrypt* the contents of the data *without knowing the key*.

An oracle refers to a "hint" that provides an attacker with information about whether or not the action he is executing is correct. Imagine you are playing a board or card game with a child: his face lights up with a big smile when he thinks he is about to make a good move. That's an oracle. In your case, as an opponent, you can use this oracle to plan your next move accordingly.

Stuffing is a specific cryptographic term. Some ciphers, which are the algorithms used to encrypt data, work on *blocks of data* where each block has a fixed size. If the data you want to encrypt does not have the right size to fill the blocks, the data is automatically padded until it does. Many forms of padding require padding to always be present, even if the original input was the correct size. This allows the padding to always be safely removed after decryption.

By combining the two elements, a software implementation with a padding oracle reveals whether the decrypted data has a valid padding. The oracle could be something as simple as returning a value that says "Invalid padding", or something more complicated such as taking a considerably different time to process a valid block instead of an invalid one.

Block-based ciphers have another property, called "*mode*", which determines the relationship of the data in the first block to the data in the second block, and so on. One of the most commonly used modes is *CBC*. CBC presents an initial random block, known as an "*initialization vector*" (*IV*), and combines the previous block with the static encryption result so that encrypting the same message with the same key does not always generate the same encrypted output.

An attacker can use a padding oracle, in combination with the CBC way of structuring the data, to send slightly modified messages to the code exposing the oracle and keep sending data until the oracle indicates that they are correct. From this response, the attacker can decrypt the message byte by byte.

Modern computer networks are of such high quality that an attacker can detect very small differences (less than 0.1 ms) in execution time on remote systems. Applications that assume that correct decryption can only occur when data is not altered may be vulnerable to attacks from tools that are designed to observe differences in correct and incorrect decryption. While this timing difference may be more significant in some languages or libraries than others, it is now believed to be a practical threat to all languages and libraries when the application's response to the error is taken into account.

This type of attack relies on the ability to change the encrypted data and test the result against the oracle. The only way to completely mitigate the attack is to detect changes to the encrypted data and refuse to perform actions on it. The standard way to do this is to create a signature for the data and validate it before performing any operation. The signature must be verifiable and the attacker must not be able to create it; otherwise, he could modify the encrypted data and calculate a new signature based on the changed data.

A common type of proper signature is known as a "*keyed hash message authentication code*" (*HMAC*). An HMAC differs from a checksum in that it requires a secret key, which is known only to the person generating the HMAC and the person validating it. If you do not have this key, you cannot generate a correct HMAC. When you receive the data, you can take the encrypted data, independently calculate the HMAC with the secret key shared by both you and the sender, and then compare the HMAC the sender sends against the one you calculated. This comparison must be of constant time; otherwise, you will have added another detectable oracle, thus allowing a different type of attack.

In summary, to safely use padded CBC block ciphers, you need to combine them with an HMAC (or other data integrity check) that is validated by a time-constant comparison before attempting to decrypt the data. Since all modified messages take the same time to generate a response, the attack is prevented.

The padding oracle attack may seem a bit complex to understand, as it involves a feedback process to guess the encrypted content and modify the padding. However, there are tools such as **PadBuster** that can automate much of the process.

**PadBuster** is a tool designed to automate the process of decrypting *CBC-mode* encrypted messages using *PKCS #7* padding. The tool allows attackers to send HTTP requests with *malicious padding* to determine whether the padding is valid or not. In this way, attackers can guess the encrypted content and decrypt the entire message.

# Example

For this example we will be using the following VulnHub machine: [Padding Oracle](https://www.vulnhub.com/entry/pentester-lab-padding-oracle,174/). We will install it as normal making sure to check the *bridged* network mode and *replicate physical network connection state*.

With **arp-scan** we can see all the computers connected to our network interface via arp and prevent it from showing duplicates:

```bash
arp-scan -I ens33 --localnet --ignoredups
```

Once the victim machine is located we can ping it to find out that it is connected and then proceed to run an **nmap** to scan the open ports:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP>
```

We can see that port *80* is open so we can enter to see the web server that is mounted on *192.168.50.104:80*.

The website allows us to register, so we register with any username and password.

We access *Storage* and see that we have an *auth cookie* with a value that is probably encrypted in *CBC* mode.

We can try to decipher it with the **padbuster** tool:

```bash
# The block that we pass it must be a multiplot of 8 bytes, in this case it will be 8
padbuster http://192.168.50.104/index.php oJ6SQZd72ATSoKtwXiP1brb5Uen0MShk 8 -cookies 'auth=oJ6SQZd72ATSoKtwXiP1brb5Uen0MShk'
```

It has managed to decrypt it and we see that the content of that block is *user=loki*, so we can reverse encrypt *user=admin* to, if the admin user is connected, steal his session:

```bash
padbuster http://192.168.50.104/index.php oJ6SQZd72ATSoKtwXiP1brb5Uen0MShk 8 -cookies 'auth=oJ6SQZd72ATSoKtwXiP1brb5Uen0MShk' -plaintext 'user=admin'
```

We can use the value generated by the **padbuster** tool to change our session cookie and steal the session from the admin.

We can also register with a user similar to *admin* and use **BurpSuite** so that, by means of a *Bit Flipper* attack, we can obtain your session cookie. In this case we will register as the user *bdmin*.

After registering, we refreshed the page to go through **BurpSuite**. There we see that we are sending the *auth* cookie from before, so we can add the auth value as a payload inside the *intrude* and try the brute force attack.

In the *Payloads* section, we must select the *payload type* as *Bit flipper*, *format of original data* as *literal value* and uncheck the *url-encode option* for special characters to avoid problems. Then we can start the attack.

Now we can sort by the length of the request, to see which ones are different. One of them should be the *admin* user, and as before we take over his auth cookie and steal his session.