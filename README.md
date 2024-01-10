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

Authentication Level-4:Register & Login using password hashing/ salting with bcrypt:
1. Install bcrypt (npm i bcrypt) and import bcrypt. If you face any issue in installation, refer to the GITHUB repos of NPM to search the solution.
2. Define the number of salt rounds: const saltRound = 10
3. Remove the usage of MD5 from import, Register and Login routes and replace them with the bcrypt hashing/salting function as detailed in the code.

Authentication Level-5: Using passport, express-session & sequelize to add Cookies & sessions to insure authenticate and de-authenticate users credentials with starts and expiries of users login sessions and server restarts:
1. Installing & importing the relevant packages express-session, passport, passport-local, sequelize & connect-flash.
2. Set up & initialize the session including the cookies properties.
3. Set Up Sequelize and create User Model with PostgreSQL
4. Initialize and start using passport
5. Configure Passport Local Strategy.
6. Update register and login routes.
7. Adding Secret Route and Logout Route.

Authentication Level-6: OAuth 2.0 & Implement Sign In with Google:
1. Create an application on the Google Developers Console.
2. Alter our Database Table to suit our app requirement (Add isgoogleaccount column).
3. Install & import the required packages ("passport-google-oauth20")
4. Configure Google strategy as defined in passport Docs & adjust it to suit our requirements.
5. Replace serializing and deserializing functions with the ones defined in passport documentation.
6. Download & copy the bootstrap-social.css to our public folder.
7. Add the Sign Up with Google Button in Register & login EJS and add the classes relevant to bootstrap-social.css.
8. Update the header.ejs with the incorporated CSS file.
9. Add “/auth/google” route.
10. Add “/auth/google/secrets” route.