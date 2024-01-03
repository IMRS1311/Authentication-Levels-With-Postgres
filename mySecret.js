import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt";

const saltRounds = 10;
const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set('view engine', 'ejs');

// --------------------------- CREATE DATABASE -------------------
/*
async function createDatabase() {
    const db = new pg.Client({
        user: "postgres",
        host: "localhost",
        database: "postgres",
        password: "secret12345",
        port: 5432,
    });
    try {
        await db.connect();
        await db.query("CREATE DATABASE userdb");
        console.log("Database created successfully!");
    } catch (err) {
        console.log(err.message);
    } finally {
        db.end();
    }
}

createDatabase();
*/

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "userdb",
    password: "secret12345",
    port: 5432,
});

db.connect();

// --------------------------- CREATE TABLES -------------------
/*
const createTableQuery = "CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(50) UNIQUE NOT NULL CHECK (email <> ''), password VARCHAR(512) NOT NULL CHECK (password <> ''))";

db.query(createTableQuery, (err, res) => {
    if (err) {
        console.log(err.message);
    } else {
        console.log("Table users created successfully!");
    }
});
*/

//  ---------------- Render Home Page -------------------
app.get("/", (req, res) => {
    res.render("home");
});

//  --------------- Render Register Page --------------------
app.get("/register", (req, res) => {
    res.render("register");
})

//  ------------- Post Register Information -----------------
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    try {
        const results = await db.query("SELECT * FROM users WHERE email = $1", [username]);
        const user = results.rows[0];
        if (user) {
            res.render("register", {message: "The Email already exist, choose another!"});
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                await db.query(`INSERT INTO users (email, password) VALUES ($1, $2)`, [username, hash]);
            });
            res.render("secrets");
        }
    } catch (err) {
        console.log(err.message);
        res.render("register", {message: "Server is not connected, please try again later!"}); 
    }
})

//  -------------- Render Login Page --------------------
app.get("/login", (req, res) => {
    res.render("login");
});

//  ------------ Post Login Information ------------------
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const query = 'SELECT email, password FROM users WHERE email = $1';
        const values = [username];
        const user = (await db.query(query, values)).rows[0];
        if (user) {
            bcrypt.compare(password, user.password, function(err, result) {
                if (result == true) {
                    res.render("secrets");
                } else {
                    res.render("login", {message: "The password is not correct, try again!"}); 
                }
            });
        } else {
            res.render("login", {message: "The username is not correct, try again!"}); 
        }
    }
    catch (err) {
        console.log(err.detail);
        res.render("login", {message: "An error occurred, please try again!"}); 
        }   
});

app.listen(port, () => {
    console.log(`Server running on port http://localhost:${port}`);
});