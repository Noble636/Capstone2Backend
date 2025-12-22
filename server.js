const express = require('express');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { files: 3, fileSize: 5 * 1024 * 1024 } });
const crypto = require('crypto');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';
const IV_LENGTH = 16;

// Deterministic encryption for username/email (fixed IV)
function encryptDeterministic(text) {
    if (!text) return '';
    // Use a fixed IV for deterministic encryption (e.g., all zeros)
    const iv = Buffer.alloc(IV_LENGTH, 0);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Standard encryption for other fields (random IV)
function encrypt(text) {
    if (!text) return '';
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptDeterministic(encrypted) {
    if (!encrypted) return '';
    const iv = Buffer.alloc(IV_LENGTH, 0);
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function decrypt(text) {
    if (!text) return '';
    let parts = text.split(':');
    let iv = Buffer.from(parts.shift(), 'hex');
    let encryptedText = parts.join(':');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

const handleDatabaseError = (res, err) => {
    console.error('Database error:', err);
    res.status(500).json({ message: 'Database error occurred' });
};

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const DEVELOPER_TOKEN = 'Token';

app.post('/api/admin/register', async (req, res) => {
    const { fullName, email, username, password, adminToken } = req.body;

    if (!fullName || !email || !username || !password || !adminToken) {
        return res.status(400).json({ message: 'Full Name, Email, Username, Password, and Admin Token are required.' });
    }

    try {
        console.log('[REGISTER] Username:', username);
        const encryptedUsername = encryptDeterministic(username);
        console.log('[REGISTER] Encrypted Username:', encryptedUsername);
        const encryptedEmail = encryptDeterministic(email);
        const [existingAdmin] = await db.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);
        if (existingAdmin.length > 0) {
            return res.status(409).json({ message: 'Username already exists for an admin account.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedAdminToken = await bcrypt.hash(adminToken, 10);
        const [result] = await db.execute(
            'INSERT INTO admins (full_name, email, username, password, admin_token) VALUES (?, ?, ?, ?, ?)',
            [fullName, encryptedEmail, encryptedUsername, hashedPassword, hashedAdminToken]
        );

        res.status(201).json({ message: 'Admin account created successfully!' });
    } catch (error) {
        console.error('Error during admin registration:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

        try {
            console.log('[LOGIN] Username:', username);
            const encryptedUsername = encryptDeterministic(username);
            console.log('[LOGIN] Encrypted Username:', encryptedUsername);
            const [admins] = await db.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);

        if (admins.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const admin = admins[0];
        const passwordMatch = await bcrypt.compare(password, admin.password);

        if (passwordMatch) {
            res.status(200).json({ message: 'Admin login successful!', adminId: admin.admin_id, fullName: admin.full_name });
        } else {
            res.status(401).json({ message: 'Invalid username or password.' });
        }
    } catch (error) {
        console.error('Error during admin login:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const [tenants] = await db.execute('SELECT tenant_id, username, password, full_name, apartment_id FROM tenants WHERE username = ?', [username]);
        if (tenants.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const tenant = tenants[0];
        const passwordMatch = await bcrypt.compare(password, tenant.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        res.status(200).json({
            message: 'Login successful',
            userId: tenant.tenant_id,
            fullName: tenant.full_name,
            apartmentId: tenant.apartment_id,
        });
    } catch (error) {
        console.error('Error during login:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/forgot-password/verify-username', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }

    try {
        const [tenantResults] = await db.execute('SELECT username, full_name, contact_number, apartment_id, email FROM tenants WHERE username = ?', [username]);
        if (tenantResults.length === 0) {
            return res.status(404).json({ message: 'Username not found' });
        }

        const tenant = tenantResults[0];
        const otp = generateOTP();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

        await db.execute(
            'INSERT INTO password_reset_otps (username, otp, expires_at) VALUES (?, ?, ?)',
            [username, otp, expiresAt]
        );

        let emailResult = null;
        if (tenant.email) {
            try {
                const { sendOtpEmail } = require('./mailer');
                await sendOtpEmail(tenant.email, otp);
                emailResult = 'OTP sent to your registered email address.';
            } catch (err) {
                console.error('Failed to send OTP email:', err);
                emailResult = 'OTP generated, but failed to send email.';
            }
        }
        res.status(200).json({
            message: emailResult || 'OTP generated.',
            userDetails: {
                username: tenant.username,
                full_name: tenant.full_name,
                contact_number: tenant.contact_number,
                apartment_id: tenant.apartment_id,
                email: tenant.email,
            },
        });
    } catch (error) {
        console.error('Error verifying username/sending OTP:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/forgot-password/verify-otp', async (req, res) => {
    const { username, otp } = req.body;

    if (!username || !otp) {
        return res.status(400).json({ message: 'Username and OTP are required' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND otp = ? AND expires_at > NOW()',
            [username, otp]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/forgot-password/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
        return res.status(400).json({ message: 'Username and new password are required' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND expires_at > NOW()',
            [username]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'OTP not verified or expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE tenants SET password = ? WHERE username = ?', [hashedPassword, username]);

        await db.execute('DELETE FROM password_reset_otps WHERE username = ?', [username]);

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error during password reset:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/submit-complaint', upload.array('images', 3), async (req, res) => {
    const { tenantId, complaint, date } = req.body;

    if (!tenantId || !complaint || !date) {
        return res.status(400).json({ message: 'Tenant ID, complaint, and date are required' });
    }

    try {
        const [result] = await db.execute(
            'INSERT INTO tenant_complaints (tenant_id, complaint_text, complaint_date, status, admin_message) VALUES (?, ?, ?, ?, ?)',
            [tenantId, complaint, date, 'Pending', null]
        );

        const complaintId = result.insertId;
        if (req.files && req.files.length > 0) {
            const files = req.files.slice(0, 3);
            let order = 1;
            for (const file of files) {
                await db.execute(
                    'INSERT INTO complaint_images (complaint_id, image_data, mime_type, filename, image_order) VALUES (?, ?, ?, ?, ?)',
                    [complaintId, file.buffer, file.mimetype || 'image/jpeg', file.originalname || null, order]
                );
                order++;
            }
        }

        res.status(201).json({ message: 'Complaint submitted successfully', complaintId });
    } catch (error) {
        console.error('Error submitting complaint:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints', async (req, res) => {
    const tenantId = req.query.tenantId;

    if (!tenantId) {
        return res.status(400).json({ message: 'Tenant ID is required to fetch complaints.' });
    }

    try {
        const [complaints] = await db.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.complaint_date, tc.submitted_at, tc.status, tc.admin_message, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            'WHERE tc.tenant_id = ? ORDER BY tc.submitted_at DESC',
            [tenantId]
        );
        if (complaints.length > 0) {
            const ids = complaints.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await db.execute(
                `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                ids
            );

            const imagesByComplaint = {};
            for (const row of imagesRows) {
                const buf = row.image_data;
                const base64 = buf ? buf.toString('base64') : null;
                const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
            }

            for (const c of complaints) {
                c.images = imagesByComplaint[c.complaint_id] || [];
            }
        }

        res.status(200).json(complaints);
    } catch (error) {
        console.error('Error fetching tenant complaints:', error);
        handleDatabaseError(res, error);
    }
});

app.put('/api/tenant/complaints/:complaintId', upload.array('images', 3), async (req, res) => {
    const { complaintId } = req.params;
    const { complaintText } = req.body;

    if (!complaintText) {
        return res.status(400).json({ message: 'Complaint text is required for updating.' });
    }

    try {
        await db.execute(
            'UPDATE tenant_complaints SET complaint_text = ? WHERE complaint_id = ?',
            [complaintText, complaintId]
        );

        if (req.files && req.files.length > 0) {
            await db.execute('DELETE FROM complaint_images WHERE complaint_id = ?', [complaintId]);

            const files = req.files.slice(0, 3);
            let order = 1;
            for (const file of files) {
                await db.execute(
                    'INSERT INTO complaint_images (complaint_id, image_data, mime_type, filename, image_order) VALUES (?, ?, ?, ?, ?)',
                    [complaintId, file.buffer, file.mimetype || 'image/jpeg', file.originalname || null, order]
                );
                order++;
            }
        }

        res.status(200).json({ message: 'Complaint updated successfully.' });
    } catch (error) {
        console.error('Error updating tenant complaint:', error);
        handleDatabaseError(res, error);
    }
});

app.delete('/api/tenant/complaints/:complaintId', async (req, res) => {
    const { complaintId } = req.params;
    try {
        const [result] = await db.execute('DELETE FROM tenant_complaints WHERE complaint_id = ?', [complaintId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Complaint not found.' });
        }
        res.status(200).json({ message: 'Complaint deleted successfully.' });
    } catch (error) {
        console.error('Error deleting complaint:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/complaints/active', async (req, res) => {
    try {
        const [activeComplaints] = await db.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.submitted_at, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            "WHERE tc.status IS NULL OR tc.status = 'Pending' " +
            'ORDER BY tc.submitted_at DESC'
        );
        if (activeComplaints.length > 0) {
            const ids = activeComplaints.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await db.execute(
                `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                ids
            );
            const imagesByComplaint = {};
            for (const row of imagesRows) {
                const base64 = row.image_data ? row.image_data.toString('base64') : null;
                const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
            }
            for (const c of activeComplaints) c.images = imagesByComplaint[c.complaint_id] || [];
        }

        res.status(200).json(activeComplaints);
    } catch (error) {
        console.error('Error fetching active complaints for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/complaints/log', async (req, res) => {
    try {
        const [complaintsLog] = await db.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.submitted_at, tc.status, tc.admin_message, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            "WHERE tc.status = 'Attended' OR tc.status = 'Declined' " +
            'ORDER BY tc.submitted_at DESC'
        );
        if (complaintsLog.length > 0) {
            const ids = complaintsLog.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await db.execute(
                `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                ids
            );
            const imagesByComplaint = {};
            for (const row of imagesRows) {
                const base64 = row.image_data ? row.image_data.toString('base64') : null;
                const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
            }
            for (const c of complaintsLog) c.images = imagesByComplaint[c.complaint_id] || [];
        }

        res.status(200).json(complaintsLog);
    } catch (error) {
        console.error('Error fetching complaints log for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.put('/api/admin/complaints/:complaintId', async (req, res) => {
    const { complaintId } = req.params;
    const { status, adminMessage } = req.body;
    const adminId = null;

    if (!status || (status !== 'Attended' && status !== 'Declined')) {
        return res.status(400).json({ message: 'Invalid status provided. Must be "Attended" or "Declined".' });
    }

    try {
        await db.query('START TRANSACTION');

        const [currentComplaint] = await db.execute(
            'SELECT status FROM tenant_complaints WHERE complaint_id = ? FOR UPDATE',
            [complaintId]
        );

        if (currentComplaint.length === 0) {
            await db.query('ROLLBACK');
            return res.status(404).json({ message: `Complaint ${complaintId} not found.` });
        }
        const oldStatus = currentComplaint[0].status;

        const [updateResult] = await db.execute(
            'UPDATE tenant_complaints SET status = ?, admin_message = ? WHERE complaint_id = ?',
            [status, adminMessage, complaintId]
        );

        if (updateResult.affectedRows > 0) {
            await db.execute(
                'INSERT INTO complaint_admin_actions (complaint_id, admin_id, action_type, old_status, new_status, action_message) VALUES (?, ?, ?, ?, ?, ?)',
                [complaintId, adminId, 'Status Update', oldStatus, status, adminMessage]
            );
            await db.query('COMMIT');
        res.status(200).json({ message: `Complaint ${complaintId} marked as ${status}.` });
        } else {
            await db.query('ROLLBACK');
            res.status(500).json({ message: 'Failed to update complaint status.' });
        }
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error updating complaint status:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/visitor-logs', async (req, res) => {
    try {
        const [visitorLogs] = await db.execute(
            'SELECT log_id, tenant_id, apartment_id, unit_owner_name, visitor_names, purpose, visit_date, time_in, created_at ' +
            'FROM visitor_logs ' +
            'ORDER BY created_at DESC'
        );
        res.status(200).json(visitorLogs);
    } catch (error) {
        console.error('Error fetching visitor logs for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/tenants', async (req, res) => {
    try {
        const [tenants] = await db.execute(
            'SELECT tenant_id, username, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number, created_at ' +
            'FROM tenants ' +
            'ORDER BY created_at DESC'
        );
        res.status(200).json(tenants);
    } catch (error) {
        console.error('Error fetching tenants for admin:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/profile/:tenantId', async (req, res) => {
    const { tenantId } = req.params;

    if (!tenantId) {
        return res.status(400).json({ message: 'Tenant ID is required.' });
    }

    try {
        const [tenant] = await db.execute(
            'SELECT tenant_id, username, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number, password FROM tenants WHERE tenant_id = ?',
            [tenantId]
        );
        if (tenant.length === 0) {
            return res.status(404).json({ message: 'Tenant not found.' });
        }
        res.status(200).json(tenant[0]);
    } catch (error) {
        console.error('Error fetching tenant profile:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/profile/:adminId', async (req, res) => {
    const { adminId } = req.params;
    if (!adminId) return res.status(400).json({ message: 'Admin ID is required.' });
    try {
        const [rows] = await db.execute('SELECT admin_id, username, full_name, email FROM admins WHERE admin_id = ?', [adminId]);
        if (rows.length === 0) return res.status(404).json({ message: 'Admin not found.' });
        const admin = rows[0];
        admin.username = decryptDeterministic(admin.username);
        admin.email = decryptDeterministic(admin.email);
        res.status(200).json(admin);
    } catch (err) {
        console.error('Error fetching admin profile:', err);
        handleDatabaseError(res, err);
    }
});

app.put('/api/admin/profile/:adminId', async (req, res) => {
    const { adminId } = req.params;
    let { username, fullName, email, currentPassword, newPassword, adminToken } = req.body;

    if (!fullName) return res.status(400).json({ message: 'Full name is required.' });

    try {
        const [admins] = await db.execute('SELECT username, password FROM admins WHERE admin_id = ?', [adminId]);
        if (admins.length === 0) return res.status(404).json({ message: 'Admin not found.' });
        const storedUsername = admins[0].username;
        const storedHashedPassword = admins[0].password;

        // Decrypt stored username for comparison
        const decryptedStoredUsername = decryptDeterministic(storedUsername);
        const usernameChanged = typeof username === 'string' && username !== decryptedStoredUsername;
        const passwordChangeRequested = !!newPassword;

        if ((usernameChanged || passwordChangeRequested) && !currentPassword) {
            return res.status(401).json({ message: 'Current password is required to change username or password.' });
        }

        if (currentPassword && (usernameChanged || passwordChangeRequested)) {
            const passwordMatch = await bcrypt.compare(currentPassword, storedHashedPassword);
            if (!passwordMatch) return res.status(401).json({ message: 'Invalid current password.' });
        }

        // Encrypt username and email before updating
        if (usernameChanged) {
            username = encryptDeterministic(username);
        } else {
            username = storedUsername;
        }
        if (email) {
            email = encryptDeterministic(email);
        }

        const setParts = ['full_name = ?', 'email = ?'];
        const params = [fullName, email];

        if (usernameChanged) {
            setParts.unshift('username = ?');
            params.unshift(username);
        }

        if (passwordChangeRequested) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            setParts.push('password = ?');
            params.push(hashedPassword);
        }
        if (adminToken) {
            console.log('Updating admin token for adminId:', adminId, 'New token:', adminToken);
            const hashedAdminToken = await bcrypt.hash(adminToken, 10);
            setParts.push('admin_token = ?');
            params.push(hashedAdminToken);
        }

        const updateQuery = `UPDATE admins SET ${setParts.join(', ')} WHERE admin_id = ?`;
        params.push(adminId);

        const [result] = await db.execute(updateQuery, params);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Admin not found or no changes made.' });

        let forceLogout = false;
        if (usernameChanged) {
            await db.execute('UPDATE password_reset_otps SET username = ? WHERE username = ?', [username, storedUsername]);
            await db.execute('UPDATE password_reset_grants SET username = ? WHERE username = ?', [username, storedUsername]);
            forceLogout = true;
        }

        res.status(200).json({ message: 'Admin account updated successfully!', forceLogout });
    } catch (err) {
        console.error('Error updating admin profile:', err);
        handleDatabaseError(res, err);
    }
});

app.put('/api/tenant/profile/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    const { username, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber, currentPassword, newPassword } = req.body;

    if (!fullName || !contactNumber || !apartmentId) {
        return res.status(400).json({ message: 'Full Name, Contact Number, and Apartment ID are required.' });
    }

    try {
        const [tenants] = await db.execute('SELECT username, password FROM tenants WHERE tenant_id = ?', [tenantId]);
        if (tenants.length === 0) {
            return res.status(404).json({ message: 'Tenant not found.' });
        }
        const storedUsername = tenants[0].username;
        const storedHashedPassword = tenants[0].password;
        const usernameChanged = typeof username === 'string' && username !== storedUsername;
        const passwordChangeRequested = !!newPassword;

        if ((usernameChanged || passwordChangeRequested) && !currentPassword) {
            return res.status(401).json({ message: 'Current password is required to change username or password.' });
        }

        if (currentPassword && (usernameChanged || passwordChangeRequested)) {
            const passwordMatch = await bcrypt.compare(currentPassword, storedHashedPassword);
            if (!passwordMatch) {
                return res.status(401).json({ message: 'Invalid current password.' });
            }
        }
        if (usernameChanged) {
            const [existing] = await db.execute('SELECT tenant_id FROM tenants WHERE username = ? AND tenant_id != ?', [username, tenantId]);
            if (existing.length > 0) {
                return res.status(409).json({ message: 'Username already taken.' });
            }
        }

        const setParts = ['full_name = ?', 'email = ?', 'contact_number = ?', 'apartment_id = ?', 'emergency_contact = ?', 'emergency_contact_number = ?'];
        const params = [fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber];

        if (usernameChanged) {
            setParts.unshift('username = ?');
            params.unshift(username);
        }

        if (passwordChangeRequested) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            setParts.push('password = ?');
            params.push(hashedPassword);
        }

        const updateQuery = `UPDATE tenants SET ${setParts.join(', ')} WHERE tenant_id = ?`;
        params.push(tenantId);

        const [result] = await db.execute(updateQuery, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Tenant not found or no changes made.' });
        }

        let forceLogout = false;
        if (usernameChanged) {
            await db.execute('UPDATE password_reset_otps SET username = ? WHERE username = ?', [username, storedUsername]);
            await db.execute('UPDATE password_reset_grants SET username = ? WHERE username = ?', [username, storedUsername]);
            forceLogout = true;
        }

        res.status(200).json({ message: 'Account updated successfully!', forceLogout });
    } catch (error) {
        console.error('Error updating tenant profile:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/forgot-password/verify-token', async (req, res) => {
    const { developerToken, username } = req.body;

    if (!developerToken) {
        return res.status(400).json({ message: 'Developer token is required.' });
    }

    if (developerToken === DEVELOPER_TOKEN) {
        // allow
        return res.status(200).json({ message: 'Developer token verified.' });
    } else {
        const [admins] = await db.execute('SELECT * FROM admins WHERE username = ?', [username]);
        if (admins.length > 0 && await bcrypt.compare(developerToken, admins[0].admin_token)) {
            // allow
            return res.status(200).json({ message: 'Admin token verified.' });
        } else {
            // deny
            return res.status(401).json({ message: 'Invalid developer or admin token.' });
        }
    }
});

app.post('/api/admin/forgot-password/verify-username', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ message: 'Username is required.' });
    }

    try {
    const [adminResults] = await db.execute('SELECT username, full_name, email FROM admins WHERE username = ?', [username]);
        if (adminResults.length === 0) {
            return res.status(404).json({ message: 'Admin username not found.' });
        }

        const admin = adminResults[0];
        const otp = generateOTP();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

        await db.execute(
            'INSERT INTO password_reset_otps (username, otp, expires_at) VALUES (?, ?, ?)',
            [username, otp, expiresAt]
        );

        let emailResult = null;
        if (admin.email) {
            try {
                const { sendOtpEmail } = require('./mailer');
                await sendOtpEmail(admin.email, otp);
                emailResult = 'OTP sent to your registered email address.';
            } catch (err) {
                console.error('Failed to send OTP email:', err);
                emailResult = 'OTP generated, but failed to send email.';
            }
        } else {
            console.log(`ADMIN OTP for ${admin.username}: ${otp}`);
            emailResult = 'OTP sent to console for verification.';
        }
        res.status(200).json({
            message: emailResult,
            adminDetails: {
                username: admin.username,
                full_name: admin.full_name,
                email: admin.email,
            },
        });
    } catch (error) {
        console.error('Error verifying admin username/sending OTP:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/forgot-password/verify-otp', async (req, res) => {
    const { username, otp } = req.body;

    if (!username || !otp) {
        return res.status(400).json({ message: 'Username and OTP are required.' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND otp = ? AND expires_at > NOW()',
            [username, otp]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        res.status(200).json({ message: 'OTP verified successfully.' });
    } catch (error) {
        console.error('Error verifying admin OTP:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/forgot-password/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
        return res.status(400).json({ message: 'Username and new password are required.' });
    }

    try {
        const [otpResults] = await db.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND expires_at > NOW()',
            [username]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'OTP verification required or expired.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE admins SET password = ? WHERE username = ?', [hashedPassword, username]);

        await db.execute('DELETE FROM password_reset_otps WHERE username = ?', [username]);

        res.status(200).json({ message: 'Admin password reset successfully!' });
    } catch (error) {
        console.error('Error during admin password reset:', error);
        handleDatabaseError(res, error);
    }
});

app.delete('/api/admin/tenants/:tenantId', async (req, res) => {
    const { tenantId } = req.params;

    if (!tenantId) {
        return res.status(400).json({ message: 'Tenant ID is required to delete an account.' });
    }

    try {
        await db.query('START TRANSACTION');

        await db.execute('DELETE FROM tenant_complaints WHERE tenant_id = ?', [tenantId]);

        await db.execute('DELETE FROM visitor_logs WHERE tenant_id = ?', [tenantId]);

        const [tenantResult] = await db.execute('DELETE FROM tenants WHERE tenant_id = ?', [tenantId]);

        if (tenantResult.affectedRows === 0) {
            await db.query('ROLLBACK');
            return res.status(404).json({ message: `Tenant account with ID '${tenantId}' not found.` });
        }

        await db.query('COMMIT');

        res.status(200).json({ message: `Tenant account with ID '${tenantId}' and associated data deleted successfully.` });

    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error deleting tenant account and associated data:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/verify-admin-token', async (req, res) => {
    const { adminId, adminToken } = req.body;
    const DEVELOPER_TOKEN = 'Token'; // Make sure this matches your hardcoded value

    if (!adminId || !adminToken) {
        return res.status(400).json({ valid: false, message: 'Admin ID and token required.' });
    }

    // Allow developer token
    if (adminToken === DEVELOPER_TOKEN) {
        return res.json({ valid: true });
    }

    try {
        const [rows] = await db.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
        if (rows.length === 0) {
            return res.status(404).json({ valid: false, message: 'Admin not found.' });
        }
        const isValid = await bcrypt.compare(adminToken, rows[0].admin_token);
        if (isValid) {
            return res.json({ valid: true });
        } else {
            return res.json({ valid: false, message: 'Invalid admin token.' });
        }
    } catch (err) {
        console.error('Error verifying admin token:', err);
        res.status(500).json({ valid: false, message: 'Server error.' });
    }
});


app.listen(port, () => {
    const baseUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;
    console.log(`Server is running on ${baseUrl}`);
});

app.post('/api/tenant/register', async (req, res) => {
    const { username, password, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber } = req.body;

    // Log the incoming registration request (excluding password)
    console.log('[REGISTER] Incoming tenant registration:', {
        username,
        fullName,
        email,
        contactNumber,
        apartmentId,
        emergencyContact,
        emergencyContactNumber
    });

    if (!username || !password || !fullName || !email || !apartmentId) {
        console.error('[REGISTER] Missing required fields:', { username, passwordPresent: !!password, fullName, email, apartmentId });
        return res.status(400).json({ message: 'Required fields are missing.' });
    }

    try {
        // Encrypt username and email deterministically for searchability
        const encryptedUsername = encryptDeterministic(username);
        const encryptedEmail = encryptDeterministic(email);
        // Encrypt contact numbers (not deterministic, not for search)
        const encryptedContactNumber = contactNumber ? encrypt(contactNumber) : null;
        const encryptedEmergencyContact = emergencyContact ? encrypt(emergencyContact) : null;
        const encryptedEmergencyContactNumber = emergencyContactNumber ? encrypt(emergencyContactNumber) : null;

        // Check if username already exists
        const [existingTenant] = await db.execute('SELECT * FROM tenants WHERE username = ?', [encryptedUsername]);
        if (existingTenant.length > 0) {
            console.warn('[REGISTER] Username already exists:', username);
            return res.status(409).json({ message: 'Username already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO tenants (username, password, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [encryptedUsername, hashedPassword, fullName, encryptedEmail, encryptedContactNumber, apartmentId, encryptedEmergencyContact, encryptedEmergencyContactNumber]
        );

        console.log('[REGISTER] Tenant registered successfully:', username);
        res.status(201).json({ message: 'Tenant registered successfully!' });
    } catch (error) {
        console.error('[REGISTER] Error during tenant registration:', error && error.stack ? error.stack : error);
        handleDatabaseError(res, error);
    }
});