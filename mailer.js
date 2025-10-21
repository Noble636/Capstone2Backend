const { Resend } = require('resend');
require('dotenv').config();

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const FROM_EMAIL = process.env.EMAIL_FROM || 'onboarding@resend.dev';
const AUDIT_EMAIL = process.env.AUDIT_EMAIL || 'tenantmaintenanceportal@gmail.com';

async function sendOtpEmail(to, otp) {
  if (!to) throw new Error('Missing recipient `to` for sendOtpEmail');

  const subject = 'Your OTP Code';
  const html = `<p>OTP for <strong>${to}</strong>: <strong>${otp}</strong></p>`;

  // If Resend is not configured, fallback to console logging
  if (!resend) {
    console.warn('RESEND_API_KEY not set — logging OTP instead of sending');
    console.log(`OTP for ${to}: ${otp}`);
    console.log(`Audit: ${AUDIT_EMAIL}`);
    return;
  }

  const recipients = [to];
  if (AUDIT_EMAIL && AUDIT_EMAIL !== to) recipients.push(AUDIT_EMAIL);

  // Send individually to each recipient and log the response/error for diagnostics
  for (const recipient of recipients) {
    try {
      console.log(`[mailer] Sending OTP to=${recipient} from=${FROM_EMAIL}`);
      const resp = await resend.emails.send({
        from: FROM_EMAIL,
        to: recipient,
        subject,
        html,
      });

      // resp may be a complex object; stringify safely
      try {
        console.log(`[mailer] Resend response for ${recipient}:`, JSON.stringify(resp));
      } catch (e) {
        console.log('[mailer] Resend response (could not stringify):', resp);
      }
    } catch (err) {
      // Resend SDK errors can contain nested info; log full error for debugging
      console.error(`[mailer] Failed to send to ${recipient}:`, err && err.message ? err.message : err);
      if (err && err.response) {
        console.error('[mailer] Resend error response:', err.response);
      }
      // continue to next recipient (audit) so one failure doesn't block the other
    }
  }
}

module.exports = { sendOtpEmail };
