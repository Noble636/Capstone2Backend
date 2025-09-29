const { Resend } = require('resend');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendOtpEmail(to, otp) {
  try {
    await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: 'tenantmaintenanceportal@gmail.com', // Force all OTPs to your own email
      subject: 'Your OTP Code',
      html: `<p>OTP for <strong>${to}</strong>: <strong>${otp}</strong></p>` // Show intended recipient in the email body
    });
    console.log('OTP email sent to tenantmaintenanceportal@gmail.com for', to);
  } catch (error) {
    console.error('Failed to send OTP email:', error);
    throw error;
  }
}

module.exports = { sendOtpEmail };
