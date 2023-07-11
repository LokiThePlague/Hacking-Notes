**GraphQL** is a query language for *APIs (Application Programming Interfaces)* that has become increasingly popular in recent years. Unlike traditional APIs that have fixed endpoints, GraphQL allows clients to request only the information they need and get a customized response based on their needs.

*Introspection* in GraphQL is a mechanism that allows customers to *get information* about the GraphQL schema of an API. This means that clients can explore and discover the data types, fields and relationships that exist in the API, which can be very useful for developers who need to build GraphQL clients. However, introspection can also be used by attackers to obtain sensitive information about the structure and data that exists in the API, which can be used to carry out more sophisticated attacks.

On the other hand, *Mutations* in GraphQL are operations that allow clients to *modify data* in the API. Unlike queries, which only allow data to be read, mutations allow clients to add, update or delete data. This means that mutations have the potential to be used to make major changes to the underlying API database. If not properly protected, mutations can be exploited by attackers to make malicious changes to the API, such as deleting important data or creating new records.

In the context of GraphQL, *IDORs* can occur when an attacker is able to guess or enumerate object identifiers (*IDs*) within the API, and can use those IDs to access objects that they should not have access to. This can occur because the API developers may not have properly implemented authentication and authorization mechanisms in their API.

For example, suppose a GraphQL API allows users to access information about their own orders using the order ID. If the API developer has not implemented proper authorization, an attacker could use GraphQL introspection to discover all existing order IDs in the API, including other users' orders. The attacker could then use these IDs to access other users' orders without proper authorization, which constitutes an IDOR.

Attackers can also use GraphQL Mutations to carry out IDOR attacks. For example, suppose a GraphQL API allows users to update their own order information. If the API developer has not properly implemented authorization, an attacker could use a mutation to update other users' order data, using the order IDs he has discovered through introspection.

In short, GraphQL is a query language for APIs that allows clients to request only the information they need. It is important for API developers to properly protect introspection and mutations to prevent malicious attacks by attackers.

----

We can find enumeration techniques in [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql).

When we have an answer from *introspection*, we can copy and paste it into [graphql-voyager](https://github.com/graphql-kit/graphql-voyager) for a cleaner and tidier look.