const dotenv = require('dotenv')
dotenv.config()

const express = require('express')
const expressSession = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
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

/**
 *  ---------------- PASSPORT ---------------
 */
app.use(passport.session())

passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async function (email, password, done) {
      try {
        const user = await prisma.user.findUnique({
          where: { email: email },
        })

        if (!user) {
          return done(null, false, { message: 'Incorrect email.' })
        }

        const isValid = await bcrypt.compare(password, user.password)

        if (!isValid) {
          return done(null, false, { message: 'Incorrect password.' })
        }

        return done(null, user)
      } catch (err) {
        return done(err)
      }
    },
  ),
)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: id },
      select: {
        id: true,
        email: true,
      },
    })
    done(null, user)
  } catch (err) {
    done(err)
  }
})

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
