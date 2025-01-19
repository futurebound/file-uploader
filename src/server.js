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
const path = require('node:path')
const fs = require('fs')

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

const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next()
  }
  res.status(401).json({ message: 'Not authenticated', redirectUrl: '/' })
  // res.redirect('/')
}

/**
 * ---------------- VIEWS ----------------
 */
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

/**
 *  ---------------- ROUTES ---------------
 */
app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

app.get('/', (req, res) => {
  res.render('index', { user: req.user })
})

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  }),
)

app.get('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      return res.status(500).json({ message: 'Error logging out' })
    }
    res.redirect('/')
  })
})

app.get('/signup', (req, res) => {
  res.render('signupForm')
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
        redirectUrl: '/',
      })
    })
  } catch (error) {
    console.error('Signup error:', error)
    res.status(500).json({ message: 'Error creating user' })
  }
})

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const folders = await prisma.folder.findMany({
      where: {
        userId: req.user.id,
      },
      include: {
        files: true,
      },
    })

    res.render('dashboard', { folders: folders })
  } catch (error) {
    console.error('Error fetching folders:', error)
    res.status(500).json({ message: 'Error fetching folders' })
  }
})

app.get('/folders', isAuthenticated, async (req, res) => {
  res.render('createFolderForm')
})

app.post('/folders', isAuthenticated, async (req, res) => {
  try {
    const { name } = req.body

    if (!name) {
      return res.status(400).json({ message: 'Folder name is required' })
    }

    const folder = await prisma.folder.create({
      data: {
        name,
        userId: req.user.id,
      },
    })

    // res.status(201).json(folder)
    res.redirect('/dashboard')
  } catch (error) {
    console.error('Create folder error:', error)
    res.status(500).json({ message: 'Error creating folder' })
  }
})

/**
 * Delete folder and all files.
 */
app.post('/folders/:folderId/delete', isAuthenticated, async (req, res) => {
  try {
    const { folderId } = req.params

    const folder = await prisma.folder.findFirst({
      where: {
        id: parseInt(folderId),
        userId: req.user.id,
      },
      include: {
        files: true,
      },
    })

    if (!folder) {
      return res
        .status(404)
        .json({ message: 'Folder not found or access denied' })
    }

    // Delete physical files
    const folderPath = path.join(
      'uploads',
      req.user.id.toString(),
      folderId.toString(),
    )
    if (fs.existsSync(folderPath)) {
      fs.rmSync(folderPath, { recursive: true, force: true })
    }

    // Delete folder and associated files from database
    await prisma.folder.delete({
      where: {
        id: parseInt(folderId),
      },
    })

    res.redirect('/dashboard')
  } catch (error) {
    console.error('Delete folder error:', error)
    res.status(500).json({ message: 'Error deleting folder' })
  }
})

app.get('/folders/:folderId/files', isAuthenticated, async (req, res) => {
  try {
    const { folderId } = req.params

    const folder = await prisma.folder.findFirst({
      where: {
        id: parseInt(folderId),
        userId: req.user.id,
      },
      include: {
        files: true,
      },
    })

    if (!folder) {
      return res
        .status(404)
        .json({ message: 'Folder not found or access denied' })
    }

    res.json(folder.files)
  } catch (error) {
    console.error('Error fetching files:', error)
    res.status(500).json({ message: 'Error fetching files' })
  }
})

app.post('/folders/:folderId/files', isAuthenticated, async (req, res) => {
  const { folderId } = req.params

  try {
    // Check if folder exists and belongs to user
    const folder = await prisma.folder.findFirst({
      where: {
        id: parseInt(folderId),
        userId: req.user.id,
      },
    })

    if (!folder) {
      return res
        .status(404)
        .json({ message: 'Folder not found or access denied' })
    }

    // Handle the upload
    upload.single('file')(req, res, async (err) => {
      if (err) {
        if (err instanceof multer.MulterError) {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res
              .status(400)
              .json({ message: 'File size too large. Maximum size is 5MB.' })
          }
          return res.status(400).json({ message: err.message })
        }
        return res.status(500).json({ message: 'Error uploading file' })
      }

      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' })
      }

      try {
        // Save file metadata to database
        const file = await prisma.file.create({
          data: {
            name: req.file.originalname,
            size: req.file.size,
            url: req.file.path, // Store the file path
            folderId: parseInt(folderId),
          },
        })

        const createFile = {
          id: file.id,
          name: file.name,
          size: file.size,
          createdAt: file.createdAt,
        }
        console.log('file uploaded successfully:', createFile)
        res.redirect('/dashboard')
      } catch (error) {
        // If database save fails, remove the uploaded file
        fs.unlink(req.file.path, () => {})
        throw error
      }
    })
  } catch (error) {
    console.error('Upload error:', error)
    res.status(500).json({ message: 'Error uploading file' })
  }
})

/**
 *  ---------------- SERVER ---------------
 */
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}!`)
})
