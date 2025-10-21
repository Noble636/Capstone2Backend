const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587, // STARTTLS
    secure: false,
    auth: {
        user: process.env.GMAIL_USER,
        pass: (process.env.GMAIL_PASS || '').replace(/\s+/g, ''), // remove accidental spaces
    },
    tls: {
        rejectUnauthorized: false
    }
});

transporter.verify((err) => {
    if (err) {
        console.error('Email transporter verification failed:', err.message || err);
    } else {
        console.log('Email transporter is ready');
    }
});

async function sendOtpEmail(to, otp) {
    if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
        console.warn('GMAIL_USER/GMAIL_PASS not set — OTP logged to console instead.');
        console.log(`OTP for ${to}: ${otp}`);
        return;
    }

    const mailOptions = {
        from: `"Tenant Portal" <${process.env.GMAIL_USER}>`,
        to,
        subject: 'Your OTP Code',
        text: `Your OTP is ${otp}. It expires in 5 minutes.`,
        html: `<p>Your OTP is <strong>${otp}</strong>. It expires in 5 minutes.</p>`
    };

    return transporter.sendMail(mailOptions);
}

module.exports = { sendOtpEmail };
