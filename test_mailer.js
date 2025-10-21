require('dotenv').config();
const { sendOtpEmail } = require('./mailer');

const to = process.env.TEST_TO || 'recipient@example.com';
const otp = process.env.TEST_OTP || '123456';

(async () => {
  try {
    await sendOtpEmail(to, otp);
    console.log('Test OTP send attempted. Check logs or inbox.');
  } catch (err) {
    console.error('Test send failed:', err);
    process.exit(1);
  }
})();
