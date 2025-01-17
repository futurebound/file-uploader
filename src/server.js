const dotenv = require('dotenv')
dotenv.config()

const express = require('express')
const expressSession = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const { PrismaClient } = require('@prisma/client')
const { PrismaSessionStore } = require('@quixo3/prisma-session-store')
const bcrypt = require('bcryptjs')
const multer = require('multer')

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
 *  ---------------- MIDDLEWARE ---------------
 */
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next()
  }
  res.status(401).json({ message: 'Not authenticated' })
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Files will be stored in uploads/userId/folderId/
    const userId = req.user.id
    const folderId = req.params.folderId
    const userDir = path.join('uploads', userId.toString())
    const folderDir = path.join(userDir, folderId.toString())

    // Create directories if they don't exist
    fs.mkdirSync(userDir, { recursive: true })
    fs.mkdirSync(folderDir, { recursive: true })

    cb(null, folderDir)
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9)
    cb(null, uniqueSuffix + path.extname(file.originalname))
  },
})

const fileFilter = (req, file, cb) => {
  // Accept only specific file types
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
  ]
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true)
  } else {
    cb(
      new Error(
        'Invalid file type. Only JPEG, PNG, GIF, and PDF files are allowed.',
      ),
      false,
    )
  }
}

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
})

/**
 *  ---------------- ROUTES ---------------
 */
app.get('/', (req, res) => {
  res.send('Server is running!')
})

app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body

    // Hash password
    const saltRounds = 10
    const hashedPassword = await bcrypt.hash(password, saltRounds)

    // Create new user
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
      select: {
        id: true,
        email: true,
      },
    })

    // Log the user in after signup
    req.login(newUser, (err) => {
      if (err) {
        return res
          .status(500)
          .json({ message: 'Error logging in after signup' })
      }
      res.status(201).json({
        message: 'User created successfully',
        user: newUser,
      })
    })
  } catch (error) {
    console.error('Signup error:', error)
    res.status(500).json({ message: 'Error creating user' })
  }
})

app.post('/login', passport.authenticate('local'), (req, res) => {
  res.json({ message: 'Logged in successfully' })
})

app.post('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error logging out' })
    }
    res.json({ message: 'Logged out successfully' })
  })
})

app.get('/folders', isAuthenticated, async (req, res) => {
  try {
    const folders = await prisma.folder.findMany({
      where: {
        userId: req.user.id,
      },
      include: {
        files: true,
      },
    })

    res.json(folders)
  } catch (error) {
    console.error('Error fetching folders:', error)
    res.status(500).json({ message: 'Error fetching folders' })
  }
})

/**
 *  ---------------- SERVER ---------------
 */
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`)
})
