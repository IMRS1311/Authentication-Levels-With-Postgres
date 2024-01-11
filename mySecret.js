import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import dotenv from 'dotenv';
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import Sequelize from "sequelize";
import flash from "connect-flash";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

dotenv.config();
const saltRounds = 10;
const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 1000 * 60 * 60 * 24 // Optional: cookie expiry
    }
}));

// --------- Set Up Sequelize with PostgreSQL
const sequelize = new Sequelize("userdb", "postgres", "secret12345",  {
    host: 'localhost',
    dialect: 'postgres',
    port: 5432,
    logging: false, // Disables logging
});

// --------- Create a User Model
const User = sequelize.define("user", {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    email: {
        type: Sequelize.STRING(100),
        unique: true
    },
    password: {
        type: Sequelize.STRING(512),
        allowNull: false,
        validate: {
            notEmpty: true
        }
    },
    externalid: {
        type: Sequelize.STRING(512),
        allowNull: false,
    },
    idsource: {
        type: Sequelize.STRING(50),
        allowNull: false,
    },
    secret: {
        type: Sequelize.TEXT,
    }
}, {
    timestamps: false,
    tableName: "users",
    freezeTableName: true
});

sequelize.sync(); // This line will create the table if it does not exist

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// ---------- Configure Passport Local Strategy ----------
passport.use(new LocalStrategy(
    {
        usernameField: "username", // Specify the field name that holds the email
        passwordField: "password" // Specify the field name that holds the password
    },
    async (username, password, done) => {
        try {
            // Find the user by email instead of username
            const user = await User.findOne({ where: { email: username } });
            if (!user) {
                return done(null, false, { message: "The username is not correct, try again!" });
            }

            // Compare the provided password with the stored hashed password
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, { message: "The password is not correct, try again!" });
            }

            return done(null, user);
        } catch (error) {
            return done(null, false, { message: "An error occurred, please try again." });
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findByPk(id).then(user => {
        if (user) {
            done(null, user);
        } else {
            done(null, false); // or handle invalid user
        }
    }).catch(error => {
        done(error, null);
    });
});


// -------- Setup Google Strategy --------
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    // userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    async function(accessToken, refreshToken, profile, cb) {
        console.log(profile);
        const password = Array(16).fill(null).map(() => Math.random().toString(36).charAt(2)).join('');
        User.findOrCreate({
            where: { externalid: profile.id },
            defaults: {
                // Other defaults if necessary
                //email: profile.emails[0].value,
                password: await bcrypt.hash(password, saltRounds), // Hashing the password inline
                externalid: profile.id,
                idsource: "Google"
            }
        })
        .then(([user, created]) => {
            return cb(null, user);
        })
        .catch(err => {
            return cb(err);
        });
    }
));

//  ---------------- Render Home Page -------------------
app.get("/", (req, res) => {
    res.render("home");
});

//  ---------------- Render Google Auth -------------------
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: "/register" }),
    function(req, res) {
    // Successful authentication, redirect Secrets.
        res.redirect("/secrets");
    }
);

//  --------------- Render Register Page --------------------
app.get("/register", (req, res) => {
    res.render("register");
})

//  ------------- Post Register Information -----------------
app.post('/register', async (req, res) => {
    const { username, password } = req.body; // Assuming 'username' is the user's email

    try {
        // Check if the email already exists
        const existingUser = await User.findOne({ where: { email: username } });
        if (existingUser) {
            return res.render("register", { message: "The Email already exists, choose another!" });
        }

        // Create a new user with the hashed password
        const newUser = await User.create({
            email: username,
            password: await bcrypt.hash(password, saltRounds) // Hashing the password inline
        });

        // Logging in the user using Passport
        req.login(newUser, (error) => {
            if (error) {
                console.log(error.message);
                return res.render("register", { message: "An error occurred, please try again." });
            } else {
                return res.redirect("/secrets");
            }
        });
    } catch (error) {
        console.log(error.message);
        res.render("register", { message: "An error occurred, please try again." });

    }
});

//  -------------- Render Login Page --------------------
app.get("/login", (req, res) => {
    const messages = req.flash("error"); // Assign flash messages to const to pass it as object in render 
    res.render("login", { messages: messages });
});

//  ------------ Post Login Information ------------------
app.post("/login", 
    passport.authenticate('local', {
        failureRedirect: '/login',
        failureFlash: true // Enable flash messages for failures
    }),
    (req, res) => {
        res.redirect("/secrets");
    }
);

//  ------------Get Secrets Route ------------------
app.get("/secrets", async (req, res, error) =>{
    const foundUsers = await User.findAll({
        where: {
            secret: {
                [Sequelize.Op.ne]: null  // Op.ne is the "not equal" operator
            }
        }
    });
    if (foundUsers) {
        res.render("secrets", {userWithSecrets: foundUsers});
    } else {
        console.log(error.message)        
    }
});


//  ------------ Get Submit Route ------------------
app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.cookie('connect.sid', '', { expires: new Date(0) });
        res.redirect("/login");
    }
});

//  ------------ Post Submit Route ------------------
app.post("/submit", async (req, res, error) => {
    const submittedSecret = req.body.secret;
    console.log(req.user)
    const foundUser = await User.findByPk(req.user.id);
    if (foundUser) {
        foundUser.secret = submittedSecret;
        await foundUser.save();
        res.redirect("/secrets");
    } else {
        console.log(error.message)
    }
});

//  ------------ Logout Route ------------------
app.get('/logout', (req, res) => {
    req.logout(function(error) {   // Passport's method to log out the user
        if (error) {
            console.log(error.message); 
            return next(error);
        }
        res.cookie('connect.sid', '', { expires: new Date(0) });
        res.redirect("/"); // Redirect to the homepage or login page after logout
    }); 
});

app.listen(port, () => {
    console.log(`Server running on port http://localhost:${port}`);
});
