
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { db } from './db.js';
import { auth } from './auth.js';
import { scoreTranscription } from './scoring.js';

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));
app.use(express.json({ limit: '2mb' }));

const uploadDir = path.resolve(process.env.UPLOAD_DIR || './uploads');
fs.mkdirSync(uploadDir, { recursive: true });

app.use('/uploads', express.static(uploadDir));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 250 }));

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5
});

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (_, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${safeName}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }
});

const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT || 587) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

const sign = user =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

const otp = () =>
  String(Math.floor(100000 + Math.random() * 900000));

app.get('/api/health', (_, res) => {
  res.json({ ok: true, service: 'Future Stenographers API' });
});

// Registration
app.post('/api/auth/register', otpLimiter, async (req, res) => {
  try {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(8),
      name: z.string().min(2),
      dob: z.string().optional(),
      district: z.string().min(2),
      state: z.string().min(2)
    });

    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Please check all fields. Password must be at least 8 characters.'
      });
    }

    const data = parsed.data;
    const email = data.email.toLowerCase();

    if (await db.user.findUnique({ where: { email } })) {
      return res.status(409).json({ error: 'This email is already registered.' });
    }

    const code = otp();
    const codeHash = await bcrypt.hash(code, 10);

    await db.otpCode.create({
      data: {
        email,
        codeHash,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000)
      }
    });

    if (mailer) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM,
        to: email,
        subject: 'Future Stenographers email verification',
        text: `Your verification code is ${code}. It expires in 10 minutes.`
      });
    } else if (process.env.NODE_ENV === 'development') {
      console.log(`[DEV ONLY] OTP for ${email}: ${code}`);
    } else {
      return res.status(503).json({ error: 'Email service is not configured.' });
    }

    const passwordHash = await bcrypt.hash(data.password, 12);

    await db.user.create({
      data: {
        email,
        passwordHash,
        name: data.name,
        dob: data.dob ? new Date(data.dob) : undefined,
        district: data.district,
        state: data.state
      }
    });

    res.json({ message: 'Verification code sent. Please verify your email.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// Email verification
app.post('/api/auth/verify', otpLimiter, async (req, res) => {
  try {
    const parsed = z.object({
      email: z.string().email(),
      code: z.string().length(6)
    }).safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid email or code.' });
    }

    const email = parsed.data.email.toLowerCase();

    const record = await db.otpCode.findFirst({
      where: { email },
      orderBy: { createdAt: 'desc' }
    });

    if (
      !record ||
      record.expiresAt < new Date() ||
      !(await bcrypt.compare(parsed.data.code, record.codeHash))
    ) {
      return res.status(400).json({ error: 'Code is invalid or expired.' });
    }

    const user = await db.user.update({
      where: { email },
      data: { verifiedAt: new Date() }
    });

    await db.otpCode.deleteMany({ where: { email } });

    res.json({
      token: sign(user),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// Login
app.post('/api/auth/login', otpLimiter, async (req, res) => {
  try {
    const parsed = z.object({
      email: z.string().email(),
      password: z.string()
    }).safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: 'Enter a valid email and password.' });
    }

    const user = await db.user.findUnique({
      where: { email: parsed.data.email.toLowerCase() }
    });

    if (
      !user ||
      !user.verifiedAt ||
      !(await bcrypt.compare(parsed.data.password, user.passwordHash))
    ) {
      return res.status(401).json({
        error: 'Invalid credentials or email not verified.'
      });
    }

    res.json({
      token: sign(user),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// Student profile
app.get('/api/me', auth(), async (req, res) => {
  const user = await db.user.findUnique({
    where: { id: req.user.id },
    select: {
      id: true,
      email: true,
      name: true,
      dob: true,
      district: true,
      state: true,
      role: true
    }
  });

  res.json(user);
});

app.patch('/api/me', auth(), async (req, res) => {
  const parsed = z.object({ name: z.string().min(2) }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid name.' });
  }

  const user = await db.user.update({
    where: { id: req.user.id },
    data: parsed.data,
    select: { id: true, email: true, name: true }
  });

  res.json(user);
});

app.post('/api/me/password', auth(), async (req, res) => {
  const parsed = z.object({
    currentPassword: z.string(),
    newPassword: z.string().min(8)
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'New password must be at least 8 characters.'
    });
  }

  const user = await db.user.findUnique({
    where: { id: req.user.id }
  });

  if (!user || !(await bcrypt.compare(parsed.data.currentPassword, user.passwordHash))) {
    return res.status(400).json({ error: 'Current password is incorrect.' });
  }

  await db.user.update({
    where: { id: user.id },
    data: {
      passwordHash: await bcrypt.hash(parsed.data.newPassword, 12)
    }
  });

  res.json({ message: 'Password updated.' });
});

// Student courses and tests
app.get('/api/courses', auth(), async (req, res) => {
  res.json(await db.course.findMany({ orderBy: { createdAt: 'desc' } }));
});

app.get('/api/my/courses', auth(), async (req, res) => {
  res.json(await db.courseAssignment.findMany({
    where: { userId: req.user.id },
    include: { course: true }
  }));
});

app.get('/api/series', auth(), async (req, res) => {
  const assigned = await db.testSeriesAssignment.findMany({
    where: { userId: req.user.id },
    select: { seriesId: true }
  });

  const ids = assigned.map(item => item.seriesId);

  res.json(await db.testSeries.findMany({
    where: {
      OR: [
        { access: 'FREE' },
        { id: { in: ids } }
      ]
    },
    include: { classes: true }
  }));
});

app.get('/api/dictations', auth(), async (req, res) => {
  res.json(await db.dictation.findMany({
    select: {
      id: true,
      title: true,
      language: true,
      category: true,
      createdAt: true
    },
    orderBy: { createdAt: 'desc' }
  }));
});

app.get('/api/dictations/:id/audio', auth(), async (req, res) => {
  const dictation = await db.dictation.findUnique({
    where: { id: req.params.id }
  });

  if (!dictation) return res.sendStatus(404);

  res.json({
    audioUrl: `${req.protocol}://${req.get('host')}/uploads/${path.basename(dictation.audioPath)}`,
    title: dictation.title
  });
});

app.post('/api/dictations/:id/submit', auth(), async (req, res) => {
  const parsed = z.object({
    text: z.string(),
    elapsedMinutes: z.number().positive()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid submission.' });
  }

  const dictation = await db.dictation.findUnique({
    where: { id: req.params.id }
  });

  if (!dictation) return res.sendStatus(404);

  const result = scoreTranscription(
    dictation.referenceText,
    parsed.data.text,
    parsed.data.elapsedMinutes
  );

  const attempt = await db.testAttempt.create({
    data: {
      userId: req.user.id,
      dictationId: dictation.id,
      submittedText: parsed.data.text,
      accuracy: result.accuracy,
      wpm: result.wpm,
      errors: result.errors,
      resultJson: result
    }
  });

  res.json({ attemptId: attempt.id, ...result });
});

app.get('/api/my/history', auth(), async (req, res) => {
  res.json(await db.testAttempt.findMany({
    where: { userId: req.user.id },
    include: {
      dictation: {
        select: { title: true, language: true }
      }
    },
    orderBy: { createdAt: 'desc' }
  }));
});

app.get('/api/typing', auth(), async (req, res) => {
  res.json(await db.typingParagraph.findMany({
    orderBy: { createdAt: 'desc' }
  }));
});

// Admin routes
app.get('/api/admin/students', auth('ADMIN'), async (req, res) => {
  const search = String(req.query.search || '');

  res.json(await db.user.findMany({
    where: {
      role: 'STUDENT',
      ...(search ? { email: { contains: search, mode: 'insensitive' } } : {})
    },
    select: {
      id: true,
      email: true,
      name: true,
      dob: true,
      district: true,
      state: true,
      createdAt: true
    },
    take: 100
  }));
});

app.post('/api/admin/dictations', auth('ADMIN'), upload.single('audio'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Audio file is required.' });
  }

  const parsed = z.object({
    title: z.string().min(2),
    referenceText: z.string().min(1),
    language: z.enum(['HINDI', 'ENGLISH']),
    categoryId: z.string().optional()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Title, language and reference transcription are required.'
    });
  }

  const dictation = await db.dictation.create({
    data: { ...parsed.data, audioPath: req.file.path }
  });

  res.status(201).json({ id: dictation.id, title: dictation.title });
});

app.post('/api/admin/categories', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({ name: z.string().min(2) }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Category name required.' });
  }

  res.status(201).json(await db.dictationCategory.create({
    data: parsed.data
  }));
});

app.post('/api/admin/courses', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({
    title: z.string().min(2),
    description: z.string(),
    features: z.array(z.string()).default([]),
    pricePaise: z.number().int().nonnegative(),
    thumbnailUrl: z.string().optional(),
    demoUrl: z.string().optional()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid course data.' });
  }

  res.status(201).json(await db.course.create({ data: parsed.data }));
});

app.post('/api/admin/assign-course', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({
    userId: z.string(),
    courseId: z.string()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid assignment.' });
  }

  res.json(await db.courseAssignment.upsert({
    where: { userId_courseId: parsed.data },
    create: parsed.data,
    update: {}
  }));
});

app.post('/api/admin/series', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({
    title: z.string().min(2),
    description: z.string().optional(),
    access: z.enum(['FREE', 'PAID']),
    thumbnailUrl: z.string().optional()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid series data.' });
  }

  res.status(201).json(await db.testSeries.create({ data: parsed.data }));
});

app.post('/api/admin/series/:id/classes', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({
    title: z.string().min(2),
    youtubeUrl: z.string().url()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid class data.' });
  }

  res.status(201).json(await db.testClass.create({
    data: { ...parsed.data, seriesId: req.params.id }
  }));
});

app.post('/api/admin/assign-series', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({
    userId: z.string(),
    seriesId: z.string()
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid assignment.' });
  }

  res.json(await db.testSeriesAssignment.upsert({
    where: { userId_seriesId: parsed.data },
    create: parsed.data,
    update: {}
  }));
});

app.post('/api/admin/typing', auth('ADMIN'), async (req, res) => {
  const parsed = z.object({
    title: z.string().min(2),
    text: z.string().min(1),
    language: z.enum(['HINDI', 'ENGLISH'])
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid paragraph.' });
  }

  res.status(201).json(await db.typingParagraph.create({
    data: parsed.data
  }));
});

app.get('/api/admin/attempts', auth('ADMIN'), async (req, res) => {
  res.json(await db.testAttempt.findMany({
    include: {
      user: {
        select: { name: true, email: true, district: true, state: true }
      },
      dictation: {
        select: { title: true }
      }
    },
    orderBy: { createdAt: 'desc' },
    take: 200
  }));
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

const port = Number(process.env.PORT || 4000);

app.listen(port, () => {
  console.log(`Future Stenographers API listening on ${port}`);
});
                
