require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const multer = require('multer');
const csvParser = require('csv-parser');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { Worker, Queue } = require('bullmq');
const IORedis = require('ioredis');
const moment = require('moment');
const dns = require('dns').promises;
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

// Initialize Express app
const app = express();

// Configure multer for file uploads
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'text/csv' || file.mimetype === 'application/vnd.ms-excel') {
      cb(null, true);
    } else {
      cb(new Error('Only CSV files are allowed'), false);
    }
  }
});

console.log('📦 Initializing Bulk Email Sender...');

// Enhanced rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000, // limit each IP to 100 requests per windowMs in production
  message: 'Too many requests from this IP, please try again later',
  skipFailedRequests: true,
  standardHeaders: true,
  legacyHeaders: false
});

// Security and performance middleware
app.use(helmet());
app.use(compression());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// CORS configuration for production
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.CORS_ORIGIN.split(',') 
    : '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
};

// Enable CORS for all routes
app.use(cors(corsOptions));
app.options('/send-mails', cors(corsOptions));
app.options('/queue-mails', cors(corsOptions));

// Body parser and rate limiting
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(limiter);

console.log('🔒 Middleware configured');

// Redis connection with enhanced configuration
console.log('🔌 Connecting to Redis...');
const redisConfig = {
  socket: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT),
    tls: true, // Explicitly enable TLS
    servername: process.env.REDIS_HOST, // Critical for Redis Cloud
    rejectUnauthorized: false // Required for Render's network
  },
  username: process.env.REDIS_USERNAME || 'default',
  password: process.env.REDIS_PASSWORD,
  maxRetriesPerRequest: null,
  enableOfflineQueue: false,
  connectTimeout: 10000
};

// For ioredis v5+ (recommended)
const connection = new IORedis(redisConfig);

// // Alternative for older versions:
// const connection = new IORedis({
//   ...redisConfig,
//   tls: redisConfig.socket.tls,
//   host: redisConfig.socket.host,
//   port: redisConfig.socket.port
// });

connection.on('connect', () => {
  console.log('🟢 Redis connection established');
  connection.info()
    .then(info => {
      const version = info.match(/redis_version:(\d+\.\d+\.\d+)/)?.[1] || 'unknown';
      console.log(`ℹ️ Redis v${version}, mode: ${info.match(/redis_mode:(\w+)/)?.[1]}`);
    })
    .catch(err => console.error('Redis version check failed:', err));
});

connection.on('ready', () => console.log('🚀 Redis client ready'));
connection.on('reconnecting', () => console.log('🔁 Redis reconnecting'));
connection.on('close', () => console.log('🔌 Redis connection closed'));
connection.on('error', (err) => {
  console.error('❌ Redis error:', err.message);
});

// Email queue setup with enhanced configuration
console.log('📨 Setting up email queue...');
const emailQueue = new Queue('emailQueue', {
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 1000 },
    removeOnComplete: { age: 24 * 3600 },
    removeOnFail: { age: 72 * 3600 }
  }
});

// Email transporter configuration with production-ready settings
console.log('📧 Configuring email transporter...');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: process.env.NODE_ENV === 'production'
  },
  pool: true,
  maxConnections: process.env.NODE_ENV === 'production' ? 5 : 2,
  maxMessages: 100,
  dsn: {
    id: uuidv4(),
    return: 'headers',
    notify: ['failure', 'delay'],
    recipient: process.env.EMAIL_USER
  },
  logger: process.env.NODE_ENV !== 'production',
  debug: process.env.NODE_ENV !== 'production'
});

transporter.verify()
  .then(() => console.log('✅ SMTP connection verified'))
  .catch(err => {
    console.error('❌ SMTP verification failed:', err.message);
    if (err.code === 'EAUTH') {
      console.error('⚠️ Check your email credentials and ensure:');
      console.error('1. You enabled "Less secure apps" or');
      console.error('2. Created an App Password if using 2FA');
    }
    process.exit(1); // Exit if email verification fails
  });

// Email template configuration
const DEFAULT_TEMPLATE = {
  subject: (name) => `Confirmation: College Counseling Session - ${name}`,
  generateHTML: (name) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>College Counseling Session Confirmation</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .email-container {
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 25px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }
        .content {
            padding: 25px;
        }
        .content h2 {
            color: #2c3e50;
            font-size: 20px;
            margin-top: 0;
        }
        .content p {
            margin-bottom: 20px;
        }
        .button {
            display: inline-block;
            background-color: #3498db;
            color: white !important;
            text-decoration: none;
            padding: 12px 25px;
            border-radius: 4px;
            font-weight: 500;
            margin: 15px 0;
        }
        .details {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .details h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .details ul {
            padding-left: 20px;
        }
        .details li {
            margin-bottom: 8px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 14px;
            border-top: 1px solid #eee;
        }
        .signature {
            margin-top: 30px;
        }
        .signature p {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <h1>College Counseling Session Confirmation</h1>
        </div>
        
        <div class="content">
            <h2>Dear ${name},</h2>
            
            <p>Thank you for registering for our premium college counseling session. We're excited to help you navigate your academic journey and make informed decisions about your future.</p>
            
            <p>To ensure we can provide you with the best possible guidance, please complete our brief registration form:</p>
            <p><strong>Registration Form:</strong></p>
            <p>We kindly ask you to fill out the form by clicking the button below:</p>
            <a href="https://forms.gle/nc4hTP8vd43hqtZa7" class="button">Click Here🔗</a>
            <p>This form will help us understand your academic background, interests, and goals, allowing us to tailor our session to your needs.</p>
            <div class="details">
                <h3>Session Details:</h3>
                <ul>
                    <li><strong>Date:</strong> 20th April 2025 (Sunday)</li>
                    <li><strong>Time:</strong> 2:00 PM (Afternoon)</li>
                    <li><strong>Mode:</strong> Zoom Meeting</li>
                </ul>
            </div>
            
            <p>The Zoom meeting link will be sent to you via email prior to the session. Please ensure you have a stable internet connection and a quiet environment for our consultation.</p>
            
            <p>We recommend completing the form at your earliest convenience to help us prepare personalized recommendations for you.</p>
            
            <div class="signature">
                <p>Warm regards,</p>
                <p><strong>Chandrashen Yadav</strong></p>
                <p>College Counseling Mentor</p>
                <p>AC Study Centre</p>
            </div>
        </div>
        
        <div class="footer">
            <p>© 2025 CollegeSecracy Powered by AC Study Centre. All rights reserved.</p>
            <p>If you have any questions, please reply to this email.</p>
        </div>
    </div>
</body>
</html>
`
};

// Utility functions
async function validateEmailDomain(email) {
  const domain = email.split('@')[1];
  try {
    await dns.resolveMx(domain);
    return true;
  } catch (err) {
    console.error(`❌ Domain validation failed for ${email}:`, err.message);
    return false;
  }
}

async function parseCSV(filePath) {
  console.log(`📄 Parsing ${filePath}`);
  return new Promise((resolve, reject) => {
    const recipients = [];
    let rowCount = 0;
    let hasErrors = false;
    
    fs.createReadStream(filePath)
      .on('error', err => {
        console.error('❌ File read error:', err.message);
        reject(new Error('Failed to read CSV file'));
      })
      .pipe(csvParser())
      .on('data', (row) => {
        rowCount++;
        const emailKey = Object.keys(row).find(k => k.toLowerCase() === 'email');
        const nameKey = Object.keys(row).find(k => k.toLowerCase() === 'name');
        
        if (!emailKey || !row[emailKey]) {
          console.warn(`⚠️ Missing email in row ${rowCount}`);
          hasErrors = true;
          return;
        }
        
        if (!nameKey || !row[nameKey]) {
          console.warn(`⚠️ Missing name in row ${rowCount}`);
          hasErrors = true;
          return;
        }
        
        recipients.push({
          email: row[emailKey].trim(),
          name: row[nameKey].trim()
        });
      })
      .on('end', () => {
        if (recipients.length === 0) {
          console.warn('⚠️ No valid recipients found in CSV');
          reject(new Error('No valid recipients found in CSV. Ensure file contains "name" and "email" columns'));
          return;
        }
        
        console.log(`📊 Processed ${rowCount} rows, found ${recipients.length} valid recipients`);
        if (hasErrors) {
          console.warn('⚠️ Some rows were skipped due to missing data');
        }
        resolve(recipients);
      })
      .on('error', err => {
        console.error('❌ CSV parse error:', err.message);
        reject(new Error('Invalid CSV format'));
      });
  });
}

// Core email processing function
async function processEmailBatch({ emails, csvFile }) {
  console.log('✉️ Starting email batch');
  
  if ((!emails || emails.length === 0) && !csvFile) {
    throw new Error('No recipients provided. Please provide either email list or CSV file');
  }

  let recipientList = [];
  
  if (csvFile) {
    try {
      recipientList = await parseCSV(csvFile.path);
    } finally {
      if (csvFile.path) {
        fs.unlink(csvFile.path, (err) => {
          if (err) console.error('Error deleting temp file:', err);
        });
      }
    }
  } else {
    recipientList = emails.split(/[\n,;]+/)
      .map(entry => entry.trim())
      .filter(Boolean)
      .map(entry => {
        const parts = entry.split(',');
        if (parts.length === 2) {
          return { name: parts[0].trim(), email: parts[1].trim() };
        }
        return { name: 'Student', email: entry.trim() };
      });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const [validRecipients, invalidRecipients] = recipientList.reduce(
    ([valid, invalid], recipient) => {
      if (!emailRegex.test(recipient.email)) {
        console.warn(`⚠️ Invalid email format: ${recipient.email}`);
        return [valid, [...invalid, {...recipient, error: 'Invalid email format'}]];
      }
      if (!recipient.name || recipient.name.trim() === '') {
        console.warn(`⚠️ Missing name for email: ${recipient.email}`);
        return [valid, [...invalid, {...recipient, error: 'Missing name'}]];
      }
      return [[...valid, recipient], invalid];
    },
    [[], []]
  );

  if (validRecipients.length === 0) {
    throw new Error('No valid recipients found. Ensure all entries have valid email and name');
  }

  console.log(`📧 Valid recipients: ${validRecipients.length}, Invalid: ${invalidRecipients.length}`);

  const results = await Promise.all(
    validRecipients.map(async (recipient) => {
      let attempts = 0;
      const maxAttempts = 3;
      let lastError = null;
      const { email, name } = recipient;

      // Validate domain first
      const domainValid = await validateEmailDomain(email);
      if (!domainValid) {
        return {
          email,
          name,
          status: 'failed',
          error: 'Invalid domain',
          attempts: 0
        };
      }

      const { subject, generateHTML } = DEFAULT_TEMPLATE;
      const mailOptions = {
        from: `"${process.env.EMAIL_NAME || 'CollegeSecracy Powered By ACStudyCentre'}" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: subject(name),
        html: generateHTML(name),
        headers: {
          'X-Mailer': 'BulkMailer/1.0',
          'X-Priority': '1',
          'X-Auto-Response-Suppress': 'All'
        },
        priority: 'high'
      };

      while (attempts < maxAttempts) {
        attempts++;
        try {
          const info = await transporter.sendMail(mailOptions);
          
          // Check if the email was actually accepted
          if (info.rejected && info.rejected.includes(email)) {
            throw new Error('Email was rejected by recipient server');
          }
          
          return { 
            email, 
            name, 
            status: 'sent', 
            attempts,
            messageId: info.messageId
          };
        } catch (err) {
          lastError = err;
          
          // Special handling for known error cases
          if (err.code === 'EDNS' || err.message.includes('Domain not found')) {
            return { 
              email,
              name,
              status: 'failed',
              error: 'Domain not found',
              attempts
            };
          }
          
          if (err.code === 'EENVELOPE' || err.message.includes('Invalid recipient')) {
            return {
              email,
              name,
              status: 'failed',
              error: 'Invalid recipient',
              attempts
            };
          }

          const delay = Math.min(1000 * Math.pow(2, attempts), 10000);
          console.error(`❌ Attempt ${attempts} failed for ${email}: ${err.message}`);
          if (attempts < maxAttempts) await new Promise(r => setTimeout(r, delay));
        }
      }

      return {
        email,
        name,
        status: 'failed',
        error: lastError?.message || 'Delivery failed',
        attempts
      };
    })
  );

  return {
    success: true,
    sentCount: results.filter(r => r.status === 'sent').length,
    failedCount: results.filter(r => r.status === 'failed').length,
    invalidRecipients,
    results: [...results, ...invalidRecipients.map(ir => ({
      email: ir.email,
      name: ir.name,
      status: 'invalid',
      error: ir.error || 'Invalid format',
      attempts: 0
    }))]
  };
}

app.get('/health', async (req, res) => {
  try {
    const redisStatus = connection.status;
    const tlsStatus = connection.options.tls ? 'enabled' : 'disabled';
    
    res.json({
      status: 'ok',
      redis: redisStatus,
      tls: tlsStatus,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/job-status/:jobId', async (req, res) => {
  try {
    const job = await emailQueue.getJob(req.params.jobId);
    if (!job) {
      return res.status(404).json({ 
        success: false,
        error: 'Job not found',
        timestamp: new Date().toISOString()
      });
    }

    const status = await job.getState();
    const progress = job.progress;
    const result = job.returnvalue;

    res.json({
      success: true,
      jobId: job.id,
      status,
      progress,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/send-mails', upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.body.emails && !req.file) {
      return res.status(400).json({
        success: false,
        error: 'No recipients provided. Please provide either email list or CSV file',
        timestamp: new Date().toISOString()
      });
    }

    const result = await processEmailBatch({
      emails: req.body.emails || '',
      csvFile: req.file
    });
    
    res.json({ 
      ...result, 
      timestamp: new Date().toISOString() 
    });
  } catch (err) {
    console.error('❌ Send error:', err.message);
    res.status(400).json({
      success: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/queue-mails', upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.body.emails && !req.file) {
      return res.status(400).json({
        success: false,
        error: 'No recipients provided. Please provide either email list or CSV file',
        timestamp: new Date().toISOString()
      });
    }

    const job = await emailQueue.add('sendEmails', {
      emails: req.body.emails || '',
      csvFile: req.file
    }, {
      jobId: uuidv4(),
      priority: 1
    });

    res.json({
      success: true,
      message: 'Emails queued for processing',
      jobId: job.id,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('❌ Queue error:', err.message);
    res.status(500).json({
      success: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/handle-bounce', async (req, res) => {
  try {
    const { messageId, status } = req.body;
    if (!messageId || !status) {
      return res.status(400).json({
        success: false,
        error: 'Missing messageId or status',
        timestamp: new Date().toISOString()
      });
    }

    console.log(`Email ${messageId} bounced with status: ${status}`);
    // Here you would update your database or storage
    res.status(200).json({
      success: true,
      message: 'Bounce recorded',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Worker setup
const worker = new Worker('emailQueue', async (job) => {
  try {
    console.log(`🔧 Processing job ${job.id}`);
    const result = await processEmailBatch(job.data);
    console.log(`✅ Completed job ${job.id}`);
    return result;
  } catch (err) {
    console.error(`❌ Job ${job.id} failed:`, err.message);
    throw err;
  }
}, {
  connection,
  concurrency: parseInt(process.env.WORKER_CONCURRENCY) || 3,
  limiter: {
    max: 10,
    duration: 1000
  }
});

worker.on('completed', (job) => {
  console.log(`🎉 Job ${job.id} completed successfully`);
});

worker.on('failed', (job, err) => {
  console.error(`💥 Job ${job?.id} failed:`, err.message);
});

worker.on('error', (err) => {
  console.error('❌ Worker error:', err.message);
});

// Start server
const PORT = parseInt(process.env.PORT) || 5000;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Redis: ${redisConfig.host}:${redisConfig.port}`);
  console.log(`   Worker concurrency: ${worker.opts.concurrency}`);
});

// Graceful shutdown
const shutdown = async (signal) => {
  console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);
  
  try {
    // Close worker first
    console.log('⏳ Closing worker...');
    await worker.close();
    
    // Close queue
    console.log('⏳ Closing email queue...');
    await emailQueue.close();
    
    // Close Redis connection
    console.log('⏳ Closing Redis connection...');
    await connection.quit();
    
    // Close server
    server.close(() => {
      console.log('🔌 All connections closed');
      process.exit(0);
    });
    
    // Force shutdown after 10 seconds if graceful shutdown fails
    setTimeout(() => {
      console.error('⏰ Force shutdown after timeout');
      process.exit(1);
    }, 10000);
  } catch (err) {
    console.error('Shutdown error:', err);
    process.exit(1);
  }
};

// Handle signals
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Error handling
process.on('unhandledRejection', (err) => {
  console.error('⚠️ Unhandled rejection:', err.message);
});

process.on('uncaughtException', (err) => {
  console.error('⚠️ Uncaught exception:', err.message);
  shutdown('uncaughtException').finally(() => process.exit(1));
});