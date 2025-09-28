const { Resend } = require('resend');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendOtpEmail(to, otp) {
  try {
    await resend.emails.send({
      from: 'tenantmaintenanceportal@gmail.com',
      to,
      subject: 'Your OTP Code',
      html: `<p>Your OTP code is: <strong>${otp}</strong></p>`
    });
    console.log('OTP email sent to', to);
  } catch (error) {
    console.error('Failed to send OTP email:', error);
    throw error;
  }
}

module.exports = { sendOtpEmail };
