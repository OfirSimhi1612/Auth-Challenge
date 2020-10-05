const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const morgan = require('morgan')

const app = express()

const USERS = [
    {
        email: "admin@email.com",
        name: "admin",
        password: "$2b$10$XrvT.ftIgwaweyREQv2.FepNzrDW9LLpzywyEWpfZycsxs5oC0DPi",
        isAdmin: true
    }
];

const INFORMATION = [
    {
        name: 'admin',
        info: `admin info`
    }
];

const REFRESH_TOKENS = [
];

const options = [
    {
        method: "post",
        path: "/users/register",
        description: "Register, required: email, user, password",
        example:
        {
            body:
            {
                email: "user@email.com",
                name: "user",
                password: "password"
            }
        }
    },
    {
        method: "post",
        path: "/users/login",
        description: "Login, required: valid email and password",
        example:
        {
            body:
            {
                email: "user@email.com",
                password: "password"
            }
        }
    },
    {
        method: "post",
        path: "/users/token",
        description: "Renew access token, required: valid refresh token",
        example:
        {
            headers:
            {
                token: "*Refresh Token*"
            }
        }
    },
    {
        method: "post",
        path: "/users/tokenValidate",
        description: "Access Token Validation, required: valid access token",
        example:
        {
            headers:
            {
                authorization: "Bearer *Access Token*"
            }
        }
    },
    {
        method: "get",
        path: "/api/v1/information",
        description: "Access user's information, required: valid access token",
        example:
        {
            headers:
            {
                authorization: "Bearer *Access Token*"
            }
        }
    },
    {
        method: "post",
        path: "/users/logout",
        description: "Logout, required: access token",
        example:
        {
            body:
            {
                token: "*Refresh Token*"
            }
        }
    },
    {
        method: "get",
        path: "api/v1/users",
        description: "Get users DB, required: Valid access token of admin user",
        example:
        {
            headers:
            {
                authorization:
                    "Bearer *Access Token*"
            }
        }
    }
];

app.use(express.json())
app.use(morgan('tiny'))

const newToken = (name, lifeTime) => {
    const token = jwt.sign({
        name: name
    },
        'secret',
        {
            expiresIn: lifeTime
        }
    )

    return token
};

app.options('/', async (req, res) => {

    let token = req.headers['authorization']; ``
    if (token) {
        token = token.slice(7, token.length);

        jwt.verify(token, 'secret', (error, decoded) => {
            if (error) {
                res.set('Allow', 'OPTIONS, GET, POST')
                res.status(200).send([
                    options[0],
                    options[1],
                    options[2]
                ])
            } else {
                const index = USERS.findIndex(user => user.name === decoded.name)

                if (USERS[index].isAdmin) {
                    res.set('Allow', 'OPTIONS, GET, POST')
                    res.status(200).send([
                        ...options
                    ])
                } else {

                    res.set('Allow', 'OPTIONS, GET, POST')
                    res.status(200).send([
                        ...options.slice(0, -1)
                    ])
                }
            }
        })
    } else {
        res.set('Allow', 'OPTIONS, GET, POST')
        res.status(200).send([
            options[0],
            options[1]
        ])
    }

})

app.get('/api/v1/users', async (req, res) => {

    let token = req.headers['authorization']; ``
    if (token) {
        token = token.slice(7, token.length);


        jwt.verify(token, 'secret', (error, decoded) => {
            if (error) {
                res.status(403).send({
                    message: 'Invalid Access Token'
                })

            } else {
                const index = USERS.findIndex(user => user.name === decoded.name)

                if (USERS[index].isAdmin) {
                    res.status(200).json(USERS)
                } else {

                    res.status(403).send({
                        message: 'Invalid Access Token'
                    }
                    )
                }

            }
        })
    } else {
        res.status(401).send({
            message: 'Access Token Required'
        })
    }

})

app.post('/users/token', async (req, res) => {

    let token = req.body.token;

    if (token) {
        // token = token.slice(7, token.length);

        jwt.verify(token, 'secret', (error, decoded) => {
            if (error) {
                res.status(403).send({
                    message: 'Invalid Access Token'
                })
            } else {
                res.status(200).send({
                    accessToken: newToken(decoded.name, '30s')
                }
                )
            }
        })
    } else {
        res.status(401).send({
            message: 'Access Token Required'
        })
    }

})

app.get('/api/v1/information', async (req, res) => {

    let token = req.headers['authorization'];

    if (token) {
        token = token.slice(7, token.length);

        jwt.verify(token, 'secret', (error, decoded) => {
            if (error) {
                res.status(403).send({
                    message: 'Invalid Access Token'
                })
            } else {
                const info = INFORMATION.filter(user => user.name === decoded.name)
                res.status(200).send(info.map((user) => {
                    return {
                        user: user.name,
                        info: user.info
                    }
                }))
            }
        })
    } else {
        res.status(403).send({
            message: 'Access Token Required'
        })
    }

})

app.post("/users/register", async (req, res) => {

    let newUser = req.body;
    const exists = USERS.findIndex(user => user.name === newUser.name)

    if (exists !== -1) {
        res.status(409).send('user already exists')
    }

    newUser = {
        ...newUser,
        password: await bcrypt.hash(newUser.password, 10),
        isAdmin: false
    }

    USERS.push(newUser)
    INFORMATION.push({
        name: newUser.name,
        email: newUser.email,
        info: `${newUser.name} info`
    })

    const refreshToken = newToken(newUser.name, '24h')

    REFRESH_TOKENS.push({
        name: newUser.name,
        refreshToken: refreshToken
    })


    res.status(201).send({
        message: 'Register Success',
        userName: newUser.name,
        accessToken: newToken(newUser.name, '30s'),
        refreshToken: refreshToken
    })

})

app.post("/users/login", async (req, res) => {

    const exists = USERS.findIndex(user => user.email === req.body.email)

    if (exists === -1) {
        res.status(404).send({
            message: 'cannot find user'
        })
    }

    const auth = bcrypt.compare(req.body.password, USERS[exists].password)

    if (auth) {

        const index = REFRESH_TOKENS.findIndex(user => user.email === req.body.email)

        let refreshToken = ''
        if (index === -1) {

            refreshToken = newToken(USERS[exists].name, '24h')

            REFRESH_TOKENS.push({
                name: USERS[exists].name,
                email: req.body.email,
                refreshToken: refreshToken
            })
        } else {

            REFRESH_TOKENS.splice(index, 1)

            refreshToken = newToken(USERS[exists].name, '24h')

            REFRESH_TOKENS.push({
                name: USERS[exists].name,
                email: req.body.email,
                refreshToken: refreshToken
            })
        }

        res.status(200).json({
            accessToken: newToken(USERS[exists].name, '30s'),
            refreshToken: refreshToken,
            userName: USERS[exists].name,
            isAdmin: USERS[exists].isAdmin
        })
    } else {
        res.status(403).json({
            message: "User or Password incorrect"
        })
    }

})

app.post('/users/logout', async (req, res) => {
    try {


        if (req.body.token) {
            jwt.verify(req.body.token, 'secret', (error, decoded) => {
                if (error) {
                    res.status(400).send({
                        message: 'Invalid Refresh Token'
                    })
                } else {

                    REFRESH_TOKENS.splice(REFRESH_TOKENS.indexOf(user => user.name === decoded.name), 1)

                    res.status(200).send({
                        message: 'User Logged Out Successfully'
                    })
                }
            })
        } else {
            res.status(400).send('Refresh Token Required')
        }

    } catch (error) {
        res.status(500).send(error.message)
    }
})

app.post('/users/tokenValidate', async (req, res) => {

    let token = req.headers['Authorization'];

    if (token) {
        token = token.slice(7, token.length);

        jwt.verify(token, 'secret', (error, decoded) => {
            if (error) {
                res.status(403).send({
                    message: 'Invalid Access Token'
                })
            } else {
                res.status(200).send({
                    valid: true
                })
            }
        })
    } else {
        res.status(401).send({
            message: 'Access Token Required'
        })
    }


})

app.use((req, res) => {
    res.status(404).send('unknown endpoint')
})




module.exports = app