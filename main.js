const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise')
const app = express();
const secureEnv = require('secure-env')
const PORT = parseInt(process.argv[2]) || parseInt(process.env.PORT) || 3000

global.env = secureEnv({secret:'mySecretPassword'})


// create connection pool
const pool = mysql.createPool({
	host: process.env.DB_HOST || 'localhost',
	port: parseInt(process.env.DB_PORT) || 3306,
	database: 'paf2020',
	user: global.env.DB_USER || process.env.DB_USER,
	password: global.env.DB_PASSWORD || process.env.DB_PASSWORD,
	connectionLimit: 4
})

const startApp = async (app, pool) => {
	const conn = await pool.getConnection()
	try {
		console.info('Pinging database...')
		await conn.ping()

        app.listen(PORT, () => {
            console.info(`Application started on port ${PORT} at ${new Date()}`)        
        })

    } catch(e) {
		console.error('Cannot ping database', e)
	} finally {
		conn.release()
	}
}

passport.use(new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
    async (req, username, password, done) => {
        // perform authentication

        const conn = await pool.getConnection()

        // await conn.query( 'select * from user where user_id like ? and password like sha2(?, 256)', [username, password],
        // (err, result) => {
        //     console.info('test')
        //     try {
        //         if (result.length) 
        //             return (done(null, result[0]));
        //         else 
        //             return (done(null, false));
        //     } 
        //     finally { conn.release(); }
        // })

        try {
            console.info(username, password)
            const [ result, _ ] = await conn.query( 'select * from user where user_id like ? and password like sha1(?)', [username, password],)
            if (result.length) {
                console.info('success')
                return (done(null, result[0]));
            }
            else {
                return (done(null, false));
            }
        } 
        finally { conn.release(); }

    }
));

app.use(bodyParser.urlencoded({extended: true}))
app.use(passport.initialize());

// start the app
startApp(app, pool)


const jwt = require('jsonwebtoken');

app.post('/login', passport.authenticate('local', {session: false}),
    
    // this middleware is called if auth using the local strategy is successful
    (req, resp) => {

        const currTime = (new Date()).getTime()
        
        const token = jwt.sign({ 
            sub: req.user.username,
            iss: req.user.password,
            iat: currTime,
            // exp: currTime + (1000 *60 *60),
            exp: currTime + (5000),
            data: { email: req.user.username }
        }, 'secret');

        resp.status(201).json({
            access_token: token,
            token_type: 'Bearer', 
            expire_in: 1800
        });
        

    }    
);

app.get('/customer', 

    (req, resp, next) => {
        const authHeader = req.get('Authorization');
        console.info(authHeader)
        if (!(authHeader && authHeader.startsWith('Bearer'))) {

            resp.status(403).json({error: 'Not authenticated'}); 
            return;
        }

        const token = authHeader.substring('Bearer'.length);
        try {
            console.info(token)
            req.jwtToken = jwt.verify(token, 'secret');
            next();
        } catch (e) {
            resp.status(403).json({error: e}); return;
        }
    },

    (req, resp) => {
        
        console.info('token still valid ', req.jwtToken)
    }

)        