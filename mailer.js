// mailer.js
// Utility for sending OTP emails using Nodemailer and Gmail

const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
    },
});

async function sendOtpEmail(to, otp) {
    const mailOptions = {
        from: process.env.GMAIL_USER,
        to,
        subject: 'Your OTP Code',
        text: `Your OTP code is: ${otp}. It will expire in 5 minutes.`,
    };
    return transporter.sendMail(mailOptions);
}

module.exports = { sendOtpEmail };
