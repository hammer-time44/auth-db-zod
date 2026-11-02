const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');
const bcrypt = require('bcrypt');

const app = new express();
const pool = new Pool({
    connectionString: "db-connection"
});

app.use(express.json());

// why schema? to server crashing
const CredSchema = z.object({
    username: z.string().min(4),
    password: z.string().min(6)
})

app.post("/signup", async (req, res) => {

    const { data, success, error } = CredSchema.safeParse(req.body);

    if (!success) {
        res.status(403).json({
            msg: "Incorrect inputs",
            error: JSON.parse(error)
        })
        return;
    }

    const username = data.username;
    const password = data.password;

    const response = await pool.query(`SELECT * FROM users WHERE username=$1`, [username]); // No SQL Injection
    if (response.rows.length) {
        res.status(403).json({
            msg: "Username alreadys exists"
        })
        return;
    }
    const hashedPromise = bcrypt.hash(password, 10); // since there is no await

    hashedPromise
        .then(async (hashedPassword) => {
            await pool.query(`INSERT INTO users(username, password) VALUES ($1, $2)`, [username, hashedPassword])
            res.json({
                msg: "You have signed up!"
            })
            return;
        })
        .catch((err) => {
            res.json({
                msg: "smtg went wrong, try again"
            })
        })
})

app.post("/signin", async (req, res) => {

    const { data, success, error } = CredSchema.safeParse(req.body);
    if (!success) {
        res.status(403).json({
            msg: "Incorrect inputs",
            error: JSON.parse(error)
        })
        return;
    }

    const username = data.username;
    const password = data.password;

    const response = await pool.query(`SELECT * FROM users WHERE username=$1`, [username]); // No SQL Injection
    if (!response.rows.length) {
        res.json({
            msg: "Invalid credentials"
        })
        return;
    }

    const isMatch = await bcrypt.compare(password, response.rows[0].password);
    if (!isMatch) {
        res.json({
            msg: "Password is incorrect"
        })
        return;
    }

    const token = jwt.sign({ username }, "secret-key");

    res.json({
        token
    })
    return;
})


app.listen(3000);