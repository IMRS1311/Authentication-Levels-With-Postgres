# Authentication Levels:
Authentication Level-1: Register and Login with just a username and password.

Authentication Level-2:Register and Login with encrypted password with SECRET_KEY:
1.	Define a long string secret key either by using a random generation function or preferably manually at this stage.
2.	Create the pgcrypto Extension
3.	Alter the size of password column to VARCHAR(512) to make sure it will accommodate for the encrypted password
4.	Adjust the INSERT query in post register route to include the password encryption
5.	Adjust the post login route to include the decryption process to authenticate the user login credentials

Adding/ Configuring Environment Variables & gitignore

Authentication Level-3:Register and Login using password hashing with md5:
1. Install md5 (npm i md5) and import md5
2. Remove the Encryption and calling the SECRET_KEY from Register and LOgin routes and replace them with hashing the password using md5 function.

