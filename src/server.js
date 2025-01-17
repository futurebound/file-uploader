const dotenv = require('dotenv')
dotenv.config()

const express = require('express')
const expressSession = require('express-session')
const passport = require('passport')
const { PrismaSessionStore } = require('@quixo3/prisma-session-store')
const { PrismaClient } = require('@prisma/client')

const prisma = new PrismaClient()
const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(
  expressSession({
    store: new PrismaSessionStore(prisma, {
      checkPeriod: 2 * 60 * 1000, // purge exprired sessions every 2 minutes
      dbRecordIdIsSessionId: true,
      dbRecordIdFunction: undefined,
    }),
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  }),
)

app.use(passport.session())

/**
 *  ---------------- ROUTES ---------------
 */
app.get('/', (req, res) => {
  res.send('Server is running!')
})

/**
 *  ---------------- SERVER ---------------
 */
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`)
})
