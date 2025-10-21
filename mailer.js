const { Resend } = require('resend');
require('dotenv').config();

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const FROM_EMAIL = process.env.EMAIL_FROM || 'onboarding@resend.dev';
const AUDIT_EMAIL = process.env.AUDIT_EMAIL || 'tenantmaintenanceportal@gmail.com';

async function sendOtpEmail(to, otp) {
  // Basic validation
  if (!to) {
    throw new Error('Missing recipient address for OTP email');
  }

  const subject = 'Your OTP Code';
  const html = `<p>OTP for <strong>${to}</strong>: <strong>${otp}</strong></p>`;

  // If Resend API key is not configured, fallback to logging the OTP (useful for local dev)
  if (!resend) {
    console.warn('RESEND_API_KEY not set — logging OTP to console instead of sending email.');
    console.log(`OTP for ${to}: ${otp}`);
    // Also log to the audit address
    console.log(`Audit copy intended for ${AUDIT_EMAIL}`);
    return;
  }

  try {
    // Send to the actual recipient and include the audit email as an additional recipient
    // Resend accepts a single address or an array. Sending to both ensures the audit mailbox
    // receives a copy without requiring Gmail forwarding rules.
    const toRecipients = [to];
    if (AUDIT_EMAIL && AUDIT_EMAIL !== to) toRecipients.push(AUDIT_EMAIL);

    await resend.emails.send({
      from: FROM_EMAIL,
      to: toRecipients,
      subject,
      html,
    });

    console.log(`OTP email sent to ${to} (audit: ${AUDIT_EMAIL})`);
  } catch (error) {
    console.error('Failed to send OTP email:', error);
    throw error;
  }
}

module.exports = { sendOtpEmail };
