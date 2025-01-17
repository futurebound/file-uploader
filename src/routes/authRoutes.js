import express from 'express'
import bcrypt from 'bcryptjs'
import { PrismaClient } from '@prisma/client'

const router = express.Router()
const prisma = new PrismaClient()

router.post('/signup', async (req, res) => {
  const { email, password } = req.body
  const hashedPassword = bcrypt.hashSync(password, 8)

  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    })
  } catch (err) {
    console.log(err.message)
    res.sendStatus(503)
  }
})
