Prompt 1: “Someone accidentally left a critical error log exposed on the server. Your task is to discover and view that log to extract the hidden flag. Inspect the web application’s source and use your reconnaissance skills to locate the log file

HINT: Start your reconnaissance by examining the web application's source code for comments or notes



### make sure to remove the volume mounted for templates because its not the best practiced way to do it instead add a pre-built image to the docker compose file so that everything is combined into one single image and the adversary will not have the means to access these templates through the webpage 



Prompt 2: The banking application has a login form with input validation. 
Your goal is to gain unauthorized access to the admin account.

The system appears to filter dangerous SQL keywords. Try common SQL injection techniques.

HINT:The validation checks for specific keyword patterns, but not all SQL syntax variations.
Consider alternative ways to represent the same SQL logic without using the blocked keywords.

Extra HINT: The payload structure: ' OR [condition]--

Try replacing the condition with SQLite hex literal syntax: x'[hex_value]'=[hex_value]

For example: ' OR x'31'=x'31'--

Flag yet to be added: FLAG{login_successful}  -------> add it somewhere on the dashboard after login process



Adding complex logic to the existing SQL injection:
1. validating both the user inputs to check and see if the typical sql commands are injected
2. we are expecting the challenger to use encode format payloads instead of injecting plain SQL commands


