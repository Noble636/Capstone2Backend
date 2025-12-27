// --- IMPORTS & CONSTANTS ---
const express = require('express');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const upload = multer();
const crypto = require('crypto');
const ExcelJS = require('exceljs');
dotenv.config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';
const IV_LENGTH = 16;
const app = express();
app.use(express.json());
app.use(cors());
const port = process.env.PORT || 5000;

// --- DB CONNECTION ---
let db;
async function initDb() {
    db = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME,
    });
}
initDb();

// --- MIDDLEWARE ---
app.use(express.json());
app.use(cors());

// --- DB POOL ---
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// --- UTILS ---
const handleDatabaseError = (res, err) => {
    console.error('Database error:', err);
    res.status(500).json({ message: 'Database error occurred' });
};

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const DEVELOPER_TOKEN = 'Token';

// --- ENCRYPTION HELPERS ---
function encryptDeterministic(text) {
    if (!text) return '';
    const iv = Buffer.alloc(IV_LENGTH, 0);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}
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

// --- ROUTES ---
// Get all complaints for a specific tenant (for EditComplaints and ComplaintStatus)
app.get('/api/tenant/complaints', async (req, res) => {
    const { tenantId } = req.query;
    if (!tenantId) {
        return res.status(400).json({ message: 'Missing tenantId' });
    }
    try {
        // Fetch complaints for this tenant
        const [complaints] = await dbPool.execute(
            'SELECT complaint_id, complaint_text, complaint_date, submitted_at, status, admin_message FROM tenant_complaints WHERE tenant_id = ? ORDER BY submitted_at DESC',
            [tenantId]
        );
        if (complaints.length > 0) {
            // Fetch images for these complaints
            const ids = complaints.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            let imagesByComplaint = {};
            if (ids.length > 0) {
                const [imagesRows] = await dbPool.execute(
                    `SELECT complaint_id, image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id IN (${placeholders}) ORDER BY image_order ASC`,
                    ids
                );
                imagesByComplaint = {};
                for (const row of imagesRows) {
                    const base64 = row.image_data ? row.image_data.toString('base64') : null;
                    const dataUri = base64 ? `data:${row.mime_type || 'image/jpeg'};base64,${base64}` : null;
                    if (!imagesByComplaint[row.complaint_id]) imagesByComplaint[row.complaint_id] = [];
                    imagesByComplaint[row.complaint_id].push({ image_id: row.image_id, filename: row.filename, mime_type: row.mime_type, dataUri, image_order: row.image_order });
                }
            }
            for (const c of complaints) c.images = imagesByComplaint[c.complaint_id] || [];
        }
        res.status(200).json(complaints);
    } catch (error) {
        console.error('Error fetching tenant complaints:', error);
        handleDatabaseError(res, error);
    }
});

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
        const [existingAdmin] = await dbPool.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);
        if (existingAdmin.length > 0) {
            return res.status(409).json({ message: 'Username already exists for an admin account.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedAdminToken = await bcrypt.hash(adminToken, 10);
        const [result] = await dbPool.execute(
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
            const [admins] = await dbPool.execute('SELECT * FROM admins WHERE username = ?', [encryptedUsername]);

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

app.post('/api/tenant/register', async (req, res) => {
    const { username, password, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber } = req.body;

    if (!username || !password || !fullName) {
        return res.status(400).json({ message: 'Username, password, and full name are required' });
    }

    try {
        // Encrypt sensitive fields
        const encryptedUsername = encryptDeterministic(username);
        const encryptedEmail = encryptDeterministic(email);
        const encryptedContactNumber = contactNumber ? encrypt(contactNumber) : null;
        const encryptedEmergencyContactNumber = emergencyContactNumber ? encrypt(emergencyContactNumber) : null;

        const [existingUser] = await dbPool.execute('SELECT * FROM tenants WHERE username = ?', [encryptedUsername]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await dbPool.execute(
            'INSERT INTO tenants (username, password, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [encryptedUsername, hashedPassword, fullName, encryptedEmail, encryptedContactNumber, apartmentId, emergencyContact, encryptedEmergencyContactNumber]
        );

        res.status(201).json({ message: 'Tenant registered successfully', tenantId: result.insertId });
    } catch (error) {
        console.error('Error during registration:', error);
        handleDatabaseError(res, error);
    }
});


app.post('/api/tenant/forgot-password/verify-username', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }

    try {
        const [tenantResults] = await dbPool.execute('SELECT username, full_name, contact_number, apartment_id, email FROM tenants WHERE username = ?', [username]);
        if (tenantResults.length === 0) {
            return res.status(404).json({ message: 'Username not found' });
        }

        const tenant = tenantResults[0];
        const otp = generateOTP();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

        await dbPool.execute(
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
        const [otpResults] = await dbPool.execute(
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
        const [otpResults] = await dbPool.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND expires_at > NOW()',
            [username]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'OTP not verified or expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await dbPool.execute('UPDATE tenants SET password = ? WHERE username = ?', [hashedPassword, username]);

        await dbPool.execute('DELETE FROM password_reset_otps WHERE username = ?', [username]);

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
        const [result] = await dbPool.execute(
            'INSERT INTO tenant_complaints (tenant_id, complaint_text, complaint_date, status, admin_message) VALUES (?, ?, ?, ?, ?)',
            [tenantId, complaint, date, 'Pending', null]
        );

        const complaintId = result.insertId;
        if (req.files && req.files.length > 0) {
            const files = req.files.slice(0, 3);
            let order = 1;
            for (const file of files) {
                await dbPool.execute(
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

app.post('/api/tenant/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const encryptedUsername = encryptDeterministic(username);
        const [tenants] = await dbPool.execute('SELECT tenant_id, username, password, full_name, apartment_id FROM tenants WHERE username = ?', [encryptedUsername]);
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

app.put('/api/tenant/complaints/:complaintId', upload.array('images', 3), async (req, res) => {
    const { complaintId } = req.params;
    const { complaintText } = req.body;

    if (!complaintText) {
        return res.status(400).json({ message: 'Complaint text is required for updating.' });
    }

    try {
        await dbPool.execute(
            'UPDATE tenant_complaints SET complaint_text = ? WHERE complaint_id = ?',
            [complaintText, complaintId]
        );

        if (req.files && req.files.length > 0) {
            await dbPool.execute('DELETE FROM complaint_images WHERE complaint_id = ?', [complaintId]);

            const files = req.files.slice(0, 3);
            let order = 1;
            for (const file of files) {
                await dbPool.execute(
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
        const [result] = await dbPool.execute('DELETE FROM tenant_complaints WHERE complaint_id = ?', [complaintId]);
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
        const [activeComplaints] = await dbPool.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.submitted_at, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            "WHERE tc.status IS NULL OR tc.status = 'Pending' " +
            'ORDER BY tc.submitted_at DESC'
        );
        if (activeComplaints.length > 0) {
            const ids = activeComplaints.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await dbPool.execute(
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
        const [complaintsLog] = await dbPool.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.submitted_at, tc.status, tc.admin_message, t.email ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            "WHERE tc.status = 'Attended' OR tc.status = 'Declined' " +
            'ORDER BY tc.submitted_at DESC'
        );
        if (complaintsLog.length > 0) {
            const ids = complaintsLog.map(c => c.complaint_id);
            const placeholders = ids.map(() => '?').join(',');
            const [imagesRows] = await dbPool.execute(
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
        await dbPool.query('START TRANSACTION');

        const [currentComplaint] = await dbPool.execute(
            'SELECT status FROM tenant_complaints WHERE complaint_id = ? FOR UPDATE',
            [complaintId]
        );

        if (currentComplaint.length === 0) {
            await dbPool.query('ROLLBACK');
            return res.status(404).json({ message: `Complaint ${complaintId} not found.` });
        }
        const oldStatus = currentComplaint[0].status;

        const [updateResult] = await dbPool.execute(
            'UPDATE tenant_complaints SET status = ?, admin_message = ? WHERE complaint_id = ?',
            [status, adminMessage, complaintId]
        );

        if (updateResult.affectedRows > 0) {
            await dbPool.execute(
                'INSERT INTO complaint_admin_actions (complaint_id, admin_id, action_type, old_status, new_status, action_message) VALUES (?, ?, ?, ?, ?, ?)',
                [complaintId, adminId, 'Status Update', oldStatus, status, adminMessage]
            );
            await dbPool.query('COMMIT');
        res.status(200).json({ message: `Complaint ${complaintId} marked as ${status}.` });
        } else {
            await dbPool.query('ROLLBACK');
            res.status(500).json({ message: 'Failed to update complaint status.' });
        }
    } catch (error) {
        await dbPool.query('ROLLBACK');
        console.error('Error updating complaint status:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/visitor-logs', async (req, res) => {
    try {
        const [visitorLogs] = await dbPool.execute(
            'SELECT log_id, tenant_id, apartment_id, unit_owner_name, visitor_names, purpose, visit_date, time_in, time_out, created_at ' +
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
        const [tenants] = await dbPool.execute(
            'SELECT tenant_id, username, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number, created_at ' +
            'FROM tenants ' +
            'ORDER BY created_at DESC'
        );
        // Decrypt sensitive fields for display
        const decryptedTenants = tenants.map(t => ({
            ...t,
            username: t.username ? decryptDeterministic(t.username) : '',
            email: t.email ? decryptDeterministic(t.email) : '',
            contact_number: t.contact_number ? decrypt(t.contact_number) : '',
            emergency_contact_number: t.emergency_contact_number ? decrypt(t.emergency_contact_number) : ''
        }));
        res.status(200).json(decryptedTenants);
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
        const [tenantRows] = await dbPool.execute(
            'SELECT tenant_id, username, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number, password FROM tenants WHERE tenant_id = ?',
            [tenantId]
        );
        if (tenantRows.length === 0) {
            return res.status(404).json({ message: 'Tenant not found.' });
        }
        const tenant = tenantRows[0];
        // Decrypt sensitive fields for display
        tenant.username = decryptDeterministic(tenant.username);
        tenant.email = decryptDeterministic(tenant.email);
        tenant.contact_number = tenant.contact_number ? decrypt(tenant.contact_number) : '';
        tenant.emergency_contact_number = tenant.emergency_contact_number ? decrypt(tenant.emergency_contact_number) : '';
        res.status(200).json(tenant);
    } catch (error) {
        console.error('Error fetching tenant profile:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/profile/:adminId', async (req, res) => {
    const { adminId } = req.params;
    if (!adminId) return res.status(400).json({ message: 'Admin ID is required.' });
    try {
        const [rows] = await dbPool.execute('SELECT admin_id, username, full_name, email FROM admins WHERE admin_id = ?', [adminId]);
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
        const [admins] = await dbPool.execute('SELECT username, password FROM admins WHERE admin_id = ?', [adminId]);
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

        const [result] = await dbPool.execute(updateQuery, params);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Admin not found or no changes made.' });

        let forceLogout = false;
        if (usernameChanged) {
            await dbPool.execute('UPDATE password_reset_otps SET username = ? WHERE username = ?', [username, storedUsername]);
            await dbPool.execute('UPDATE password_reset_grants SET username = ? WHERE username = ?', [username, storedUsername]);
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
        const [tenants] = await dbPool.execute('SELECT username, password FROM tenants WHERE tenant_id = ?', [tenantId]);
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
            const [existing] = await dbPool.execute('SELECT tenant_id FROM tenants WHERE username = ? AND tenant_id != ?', [username, tenantId]);
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

        const [result] = await dbPool.execute(updateQuery, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Tenant not found or no changes made.' });
        }

        let forceLogout = false;
        if (usernameChanged) {
            await dbPool.execute('UPDATE password_reset_otps SET username = ? WHERE username = ?', [username, storedUsername]);
            await dbPool.execute('UPDATE password_reset_grants SET username = ? WHERE username = ?', [username, storedUsername]);
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
        const [admins] = await dbPool.execute('SELECT * FROM admins WHERE username = ?', [username]);
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
    const [adminResults] = await dbPool.execute('SELECT username, full_name, email FROM admins WHERE username = ?', [username]);
        if (adminResults.length === 0) {
            return res.status(404).json({ message: 'Admin username not found.' });
        }

        const admin = adminResults[0];
        const otp = generateOTP();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

        await dbPool.execute(
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
        const [otpResults] = await dbPool.execute(
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
        const [otpResults] = await dbPool.execute(
            'SELECT * FROM password_reset_otps WHERE username = ? AND expires_at > NOW()',
            [username]
        );

        if (otpResults.length === 0) {
            return res.status(400).json({ message: 'OTP verification required or expired.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await dbPool.execute('UPDATE admins SET password = ? WHERE username = ?', [hashedPassword, username]);

        await dbPool.execute('DELETE FROM password_reset_otps WHERE username = ?', [username]);

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
        await dbPool.query('START TRANSACTION');

        await dbPool.execute('DELETE FROM tenant_complaints WHERE tenant_id = ?', [tenantId]);

        await dbPool.execute('DELETE FROM visitor_logs WHERE tenant_id = ?', [tenantId]);

        const [tenantResult] = await dbPool.execute('DELETE FROM tenants WHERE tenant_id = ?', [tenantId]);

        if (tenantResult.affectedRows === 0) {
            await dbPool.query('ROLLBACK');
            return res.status(404).json({ message: `Tenant account with ID '${tenantId}' not found.` });
        }

        await dbPool.query('COMMIT');

        res.status(200).json({ message: `Tenant account with ID '${tenantId}' and associated data deleted successfully.` });

    } catch (error) {
        await dbPool.query('ROLLBACK');
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
        const [rows] = await dbPool.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
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

        // Check if username already exists (search by encrypted username)
        const [existingTenant] = await dbPool.execute('SELECT * FROM tenants WHERE username = ?', [encryptedUsername]);
        if (existingTenant.length > 0) {
            console.warn('[REGISTER] Username already exists:', username);
            return res.status(409).json({ message: 'Username already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await dbPool.execute(
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

// Get all visitor logs for a specific tenant
app.get('/api/tenant/visitor-logs/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    if (!tenantId) {
        return res.status(400).json({ message: 'Missing tenantId' });
    }
    try {
        const [rows] = await dbPool.query(
            'SELECT log_id, visit_date, visitor_names, purpose, time_in, time_out FROM visitor_logs WHERE tenant_id = ? ORDER BY visit_date DESC, log_id DESC',
            [tenantId]
        );
        res.json(rows);
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

// Set time out for a visitor log
app.put('/api/tenant/visitor-logs/:logId/timeout', async (req, res) => {
    const { logId } = req.params;
    const { timeOut } = req.body;
    if (!logId || !timeOut) {
        return res.status(400).json({ message: 'Missing logId or timeOut' });
    }
    try {
        // Only allow setting time_out if not already set
        const [rows] = await dbPool.query('SELECT time_out FROM visitor_logs WHERE log_id = ?', [logId]);
        if (!rows.length) {
            return res.status(404).json({ message: 'Visitor log not found' });
        }
        if (rows[0].time_out) {
            return res.status(400).json({ message: 'Time out already set for this log' });
        }
        await dbPool.query('UPDATE visitor_logs SET time_out = ? WHERE log_id = ?', [timeOut, logId]);
        res.json({ message: 'Time out updated successfully' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.post('/api/tenant/submit-visitor', async (req, res) => {
    const { tenantId, fullName, apartmentId, visitorNames, visitDate, timeIn, purpose } = req.body;

    if (!tenantId || !fullName || !apartmentId || !visitorNames || !visitDate || !timeIn) {
        return res.status(400).json({ message: 'All visitor log fields are required.' });
    }

    try {
        const [result] = await dbPool.execute(
            'INSERT INTO visitor_logs (tenant_id, apartment_id, unit_owner_name, visitor_names, purpose, visit_date, time_in) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [tenantId, apartmentId, fullName, visitorNames, purpose || null, visitDate, timeIn]
        );
        res.status(201).json({ message: 'Visitor log submitted successfully!', logId: result.insertId });
    } catch (error) {
        console.error('Error submitting visitor log:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/export-complaints', async (req, res) => {
    try {
        const [complaints] = await dbPool.execute(
            'SELECT tc.complaint_id, t.full_name, t.apartment_id, tc.complaint_text, tc.complaint_date, tc.status, tc.admin_message ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            'ORDER BY tc.complaint_date DESC'
        );

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Tenant_Complaints_Report'); // <-- Sheet name

        worksheet.columns = [
            { header: 'Complaint ID', key: 'complaint_id', width: 15 },
            { header: 'Tenant Name', key: 'full_name', width: 25 },
            { header: 'Apartment ID', key: 'apartment_id', width: 15 },
            { header: 'Complaint', key: 'complaint_text', width: 40 },
            { header: 'Date', key: 'complaint_date', width: 20 },
            { header: 'Status', key: 'status', width: 15 },
            { header: 'Admin Message', key: 'admin_message', width: 30 }
        ];

        complaints.forEach(row => worksheet.addRow(row));

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=Tenant_Complaint_Reports.xlsx'); // <-- File name

        await workbook.xlsx.write(res);
        res.end();
    } catch (error) {
        console.error('Error exporting complaints:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/export-visitor-logs', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const adminId = req.body.adminId;
  if (!token || !(await isValidAdminToken(token, adminId))) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const [logs] = await dbPool.execute('SELECT * FROM visitor_logs');
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Tenant_Visitor_Report'); // <-- Sheet name
  worksheet.columns = [
    { header: 'Log ID', key: 'log_id' },
    { header: 'Tenant Owner', key: 'unit_owner_name' },
    { header: 'Apartment ID', key: 'apartment_id' },
    { header: 'Visitor(s)', key: 'visitor_names' },
    { header: 'Purpose', key: 'purpose' },
    { header: 'Date of Visit', key: 'visit_date' },
    { header: 'Time In', key: 'time_in' },
    { header: 'Time Out', key: 'time_out' }
  ];
  logs.forEach(log => worksheet.addRow(log));
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename=Tenant_Visitor_Reports.xlsx'); // <-- File name
  await workbook.xlsx.write(res);
  res.end();
});

app.post('/api/admin/export-accounts', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const adminId = req.body.adminId;
  console.log('[EXPORT ACCOUNTS] token:', token, 'adminId:', adminId);

  if (!token) {
    return res.status(401).json({ message: 'Missing token' });
  }

  if (token === DEVELOPER_TOKEN || (process.env.DEV_TOKEN && token === process.env.DEV_TOKEN)) {
    // proceed
  } else {
    if (!adminId) {
      return res.status(401).json({ message: 'Missing adminId' });
    }
    try {
      const [rows] = await dbPool.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
      if (!rows.length) {
        return res.status(401).json({ message: 'Admin not found' });
      }
      const adminTokenHash = rows[0].admin_token;
      const isMatch = await bcrypt.compare(token, adminTokenHash);
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid token' });
      }
    } catch (err) {
      console.error('Error validating admin token:', err);
      return res.status(500).json({ message: 'Error validating token' });
    }
  }

  try {
    const [tenants] = await dbPool.execute('SELECT * FROM tenants');
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Tenant_Account_Reports');
    worksheet.columns = [
      { header: 'Tenant ID', key: 'tenant_id' },
      { header: 'Full Name', key: 'full_name' },
      { header: 'Username', key: 'username' },
      { header: 'Email', key: 'email' },
      { header: 'Contact Number', key: 'contact_number' },
      { header: 'Apartment ID', key: 'apartment_id' },
      { header: 'Emergency Contact', key: 'emergency_contact' },
      { header: 'Emergency Contact Number', key: 'emergency_contact_number' }
    ];
    tenants.forEach(tenant => worksheet.addRow(tenant));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=Tenant_Account_Reports.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch (error) {
    console.error('Error exporting accounts:', error);
    res.status(500).json({ message: 'Error exporting accounts' });
  }
});

async function isValidAdminToken(token, adminId) {
  if (token === DEVELOPER_TOKEN || token === process.env.DEV_TOKEN) return true;
  if (!adminId) return false;
  try {
    const [rows] = await dbPool.execute('SELECT admin_token FROM admins WHERE admin_id = ?', [adminId]);
    if (rows.length === 0) return false;
    return await bcrypt.compare(token, rows[0].admin_token);
  } catch (err) {
    console.error('Error validating admin token:', err);
    return false;
  }
}

// POST endpoint for admin to add a unit
app.post('/api/admin/available-units', upload.array('images', 5), async (req, res) => {
  const { unitName, description, price } = req.body;
  const files = req.files || [];

  if (!unitName || !price) {
    return res.status(400).json({ message: 'Unit name and price are required.' });
  }

  try {
    // Insert unit info (no image fields here)
    const [result] = await dbPool.query(
      'INSERT INTO available_units (title, description, price) VALUES (?, ?, ?)',
      [unitName, description, price]
    );
    const unitId = result.insertId;

    // Insert each image into unit_images
    for (const file of files) {
      await dbPool.query(
        'INSERT INTO unit_images (unit_id, image_data, image_type) VALUES (?, ?, ?)',
        [unitId, file.buffer, file.mimetype]
      );
    }

    res.json({ success: true, unitId });
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

// Replace your current GET /api/available-units with this:
app.get('/api/available-units', async (req, res) => {
  try {
    const [units] = await dbPool.query('SELECT unit_id, title, description, price FROM available_units ORDER BY created_at DESC');
    const unitIds = units.map(u => u.unit_id);
    let imagesByUnit = {};

    if (unitIds.length > 0) {
      const [images] = await dbPool.query(
        `SELECT unit_id, image_data, image_type FROM unit_images WHERE unit_id IN (${unitIds.map(() => '?').join(',')})`,
        unitIds
      );
      for (const img of images) {
        const dataUri = img.image_data
          ? `data:${img.image_type};base64,${img.image_data.toString('base64')}`
          : null;
        if (!imagesByUnit[img.unit_id]) imagesByUnit[img.unit_id] = [];
        imagesByUnit[img.unit_id].push({ dataUri });
      }
    }

    const result = units.map(unit => ({
      ...unit,
      images: imagesByUnit[unit.unit_id] || []
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

app.post('/api/admin/available-units', upload.array('images', 5), async (req, res) => {
  const { unitName, description, price } = req.body;
  const files = req.files || [];

  if (!unitName || !price) {
    return res.status(400).json({ message: 'Unit name and price are required.' });
  }

  try {
    // Insert unit info (no image fields here)
    const [result] = await dbPool.query(
      'INSERT INTO available_units (title, description, price) VALUES (?, ?, ?)',
      [unitName, description, price]
    );
    const unitId = result.insertId;

    // Insert each image into unit_images
    for (const file of files) {
      await dbPool.query(
        'INSERT INTO unit_images (unit_id, image_data, image_type) VALUES (?, ?, ?)',
        [unitId, file.buffer, file.mimetype]
      );
    }

    res.json({ success: true, unitId });
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

// Replace your current GET /api/available-units with this:
app.get('/api/available-units', async (req, res) => {
  try {
    const [units] = await dbPool.query('SELECT unit_id, title, description, price FROM available_units ORDER BY created_at DESC');
    const unitIds = units.map(u => u.unit_id);
    let imagesByUnit = {};

    if (unitIds.length > 0) {
      const [images] = await dbPool.query(
        `SELECT unit_id, image_data, image_type FROM unit_images WHERE unit_id IN (${unitIds.map(() => '?').join(',')})`,
        unitIds
      );
      for (const img of images) {
        const dataUri = img.image_data
          ? `data:${img.image_type};base64,${img.image_data.toString('base64')}`
          : null;
        if (!imagesByUnit[img.unit_id]) imagesByUnit[img.unit_id] = [];
        imagesByUnit[img.unit_id].push({ dataUri });
      }
    }

    const result = units.map(unit => ({
      ...unit,
      images: imagesByUnit[unit.unit_id] || []
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

// POST new inquiry
app.post('/api/unit-inquiries', async (req, res) => {
  const { unit_id, sender_name, message } = req.body;
  if (!unit_id || !sender_name || !message) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }
  try {
    await db.execute(
      'INSERT INTO unit_inquiries (unit_id, sender_name, message, sender) VALUES (?, ?, ?, ?)',
      [unit_id, sender_name, message, 'tenant']
    );
    res.json({ message: 'Inquiry sent.' });
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});

// GET: Get all inquiries for a user by name
app.get('/api/unit-inquiries', async (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ message: 'Name is required.' });
  try {
    const [rows] = await dbPool.query(
      'SELECT * FROM unit_inquiries WHERE sender_name = ? ORDER BY created_at',
      [name]
    );
    res.json(rows);
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// GET: Admin fetches all inquiries
app.get('/api/admin/inbox', async (req, res) => {
  try {
    const [rows] = await dbPool.query('SELECT * FROM unit_inquiries ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// POST: Admin replies to an inquiry
app.post('/api/admin/inbox/reply', async (req, res) => {
  const { inquiryId, reply } = req.body;
  if (!inquiryId || !reply) return res.status(400).json({ message: 'inquiryId and reply are required.' });
  try {
    await dbPool.query('UPDATE unit_inquiries SET reply = ? WHERE inquiry_id = ?', [reply, inquiryId]);
    res.json({ success: true });
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

// GET: Inquiry history by unit ID and sender name
app.get('/api/unit-inquiries/history', async (req, res) => {
  const { unit_id, sender_name } = req.query;
  if (!unit_id || !sender_name) {
    return res.status(400).json({ message: 'unit_id and sender_name are required.' });
  }
  try {
    const [rows] = await dbPool.query(
      'SELECT * FROM unit_inquiries WHERE unit_id = ? AND sender_name = ? ORDER BY created_at',
      [unit_id, sender_name]
    );
    res.json(rows);
  } catch (err) {
    handleDatabaseError(res, err);
  }
});

app.get('/api/tenant/complaints/:complaintId/images', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [images] = await dbPool.execute(
            'SELECT image_id, image_data, mime_type, filename, image_order FROM complaint_images WHERE complaint_id = ? ORDER BY image_order',
            [complaintId]
        );
        const imageList = images.map(img => ({
            image_id: img.image_id,
            filename: img.filename,
            mime_type: img.mime_type,
            dataUri: img.image_data ? `data:${img.mime_type};base64,${img.image_data.toString('base64')}` : null,
            image_order: img.image_order
        }));
        res.json(imageList);
    } catch (error) {
        console.error('Error fetching complaint images:', error);
        handleDatabaseError(res, error);
    }
});

app.delete('/api/tenant/complaints/:complaintId/images/:imageId', async (req, res) => {
    const { complaintId, imageId } = req.params;
    if (!complaintId || !imageId) {
        return res.status(400).json({ message: 'Complaint ID and Image ID are required.' });
    }
    try {
        const [result] = await dbPool.execute(
            'DELETE FROM complaint_images WHERE complaint_id = ? AND image_id = ?',
            [complaintId, imageId]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Image not found.' });
        }
        res.status(200).json({ message: 'Image deleted successfully.' });
    } catch (error) {
        console.error('Error deleting complaint image:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/complaints/:complaintId/images', upload.single('image'), async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId || !req.file) {
        return res.status(400).json({ message: 'Complaint ID and image file are required.' });
    }
    try {
        const imageData = req.file.buffer;
        const mimeType = req.file.mimetype;
        const filename = req.file.originalname;

        // Insert the new image
        const [result] = await dbPool.execute(
            'INSERT INTO complaint_images (complaint_id, image_data, mime_type, filename, image_order) VALUES (?, ?, ?, ?, ?)',
            [complaintId, imageData, mimeType, filename, 1]
        );

        res.status(201).json({ message: 'Image uploaded successfully.', imageId: result.insertId });
    } catch (error) {
        console.error('Error uploading complaint image:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/notifications/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    if (!tenantId) {
        return res.status(400).json({ message: 'Tenant ID is required.' });
    }
    try {
        const [notifications] = await dbPool.execute(
            'SELECT * FROM notifications WHERE tenant_id = ? ORDER BY created_at DESC',
            [tenantId]
        );
        res.json(notifications);
    } catch (error) {
        console.error('Error fetching tenant notifications:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/notifications', async (req, res) => {
    const { tenantId, title, message } = req.body;
    if (!tenantId || !title || !message) {
        return res.status(400).json({ message: 'Tenant ID, title, and message are required.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO notifications (tenant_id, title, message) VALUES (?, ?, ?)',
            [tenantId, title, message]
        );
        res.json({ message: 'Notification sent.' });
    } catch (error) {
        console.error('Error sending notification:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints/:complaintId/admin-actions', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [actions] = await dbPool.execute(
            'SELECT * FROM complaint_admin_actions WHERE complaint_id = ? ORDER BY action_time DESC',
            [complaintId]
        );
        res.json(actions);
    } catch (error) {
        console.error('Error fetching complaint admin actions:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/complaints/:complaintId/admin-actions', async (req, res) => {
    const { complaintId } = req.params;
    const { actionType, oldStatus, newStatus, adminMessage } = req.body;
    if (!complaintId || !actionType || !oldStatus || !newStatus) {
        return res.status(400).json({ message: 'Complaint ID, action type, old status, and new status are required.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO complaint_admin_actions (complaint_id, admin_id, action_type, old_status, new_status, action_message) VALUES (?, ?, ?, ?, ?, ?)',
            [complaintId, null, actionType, oldStatus, newStatus, adminMessage]
        );
        res.json({ message: 'Admin action recorded.' });
    } catch (error) {
        console.error('Error recording admin action:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints/:complaintId/status-history', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [statusHistory] = await dbPool.execute(
            'SELECT * FROM complaint_status_history WHERE complaint_id = ? ORDER BY change_time DESC',
            [complaintId]
        );
        res.json(statusHistory);
    } catch (error) {
        console.error('Error fetching complaint status history:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/complaints/:complaintId/status-history', async (req, res) => {
    const { complaintId } = req.params;
    const { status, adminMessage } = req.body;
    if (!complaintId || !status) {
        return res.status(400).json({ message: 'Complaint ID and status are required.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO complaint_status_history (complaint_id, status, admin_message) VALUES (?, ?, ?)',
            [complaintId, status, adminMessage]
        );
        res.json({ message: 'Status history recorded.' });
    } catch (error) {
        console.error('Error recording status history:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints/:complaintId/details', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [details] = await dbPool.execute(
            'SELECT tc.complaint_id, tc.complaint_text, tc.complaint_date, tc.status, tc.admin_message, ' +
            't.full_name, t.apartment_id, t.email, t.contact_number, ' +
            'GROUP_CONCAT(DISTINCT CONCAT_WS(":", ci.image_id, ci.filename, ci.mime_type) ORDER BY ci.image_order ASC SEPARATOR ";") AS images ' +
            'FROM tenant_complaints tc ' +
            'JOIN tenants t ON tc.tenant_id = t.tenant_id ' +
            'LEFT JOIN complaint_images ci ON tc.complaint_id = ci.complaint_id ' +
            'WHERE tc.complaint_id = ? ' +
            'GROUP BY tc.complaint_id',
            [complaintId]
        );
        if (details.length > 0) {
            // Parse the images field
            details[0].images = details[0].images ? details[0].images.split(';').map(img => {
                const [image_id, filename, mime_type] = img.split(':');
                return { image_id, filename, mime_type, dataUri: `data:${mime_type};base64,${image_id}` };
            }) : [];
            res.json(details[0]);
        } else {
            res.status(404).json({ message: 'Complaint not found.' });
        }
    } catch (error) {
        console.error('Error fetching complaint details:', error);
        handleDatabaseError(res, error);
    }
});

app.put('/api/tenant/complaints/:complaintId/details', async (req, res) => {
    const { complaintId } = req.params;
    const { complaintText, status, adminMessage } = req.body;

    if (!complaintText && !status && !adminMessage) {
        return res.status(400).json({ message: 'At least one of complaintText, status, or adminMessage is required.' });
    }

    try {
        const updates = [];
        const params = [];

        if (complaintText) {
            updates.push('complaint_text = ?');
            params.push(complaintText);
        }
        if (status) {
            updates.push('status = ?');
            params.push(status);
        }
        if (adminMessage) {
            updates.push('admin_message = ?');
            params.push(adminMessage);
        }

        params.push(complaintId);

        await dbPool.execute(
            `UPDATE tenant_complaints SET ${updates.join(', ')} WHERE complaint_id = ?`,
            params
        );

        res.json({ message: 'Complaint details updated.' });
    } catch (error) {
        console.error('Error updating complaint details:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints/:complaintId/admin-replies', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [replies] = await dbPool.execute(
            'SELECT * FROM unit_inquiries WHERE complaint_id = ? AND sender = "admin" ORDER BY created_at',
            [complaintId]
        );
        res.json(replies);
    } catch (error) {
        console.error('Error fetching admin replies:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/complaints/:complaintId/admin-replies', async (req, res) => {
    const { complaintId } = req.params;
    const { message } = req.body;
    if (!complaintId || !message) {
        return res.status(400).json({ message: 'Complaint ID and message are required.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO unit_inquiries (complaint_id, message, sender) VALUES (?, ?, "admin")',
            [complaintId, message]
        );
        res.json({ message: 'Reply sent.' });
    } catch (error) {
        console.error('Error sending admin reply:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints/:complaintId/tenant-replies', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [replies] = await dbPool.execute(
            'SELECT * FROM unit_inquiries WHERE complaint_id = ? AND sender = "tenant" ORDER BY created_at',
            [complaintId]
        );
        res.json(replies);
    } catch (error) {
        console.error('Error fetching tenant replies:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/complaints/:complaintId/tenant-replies', async (req, res) => {
    const { complaintId } = req.params;
    const { message } = req.body;
    if (!complaintId || !message) {
        return res.status(400).json({ message: 'Complaint ID and message are required.' });
    }
    try {
        await dbPool.execute(
            'INSERT INTO unit_inquiries (complaint_id, message, sender) VALUES (?, ?, "tenant")',
            [complaintId, message]
        );
        res.json({ message: 'Reply sent.' });
    } catch (error) {
        console.error('Error sending tenant reply:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/tenant/complaints/:complaintId/chat-history', async (req, res) => {
    const { complaintId } = req.params;
    if (!complaintId) {
        return res.status(400).json({ message: 'Complaint ID is required.' });
    }
    try {
        const [chatHistory] = await dbPool.execute(
            'SELECT * FROM unit_inquiries WHERE complaint_id = ? ORDER BY created_at',
            [complaintId]
        );
        res.json(chatHistory);
    } catch (error) {
        console.error('Error fetching chat history:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/unit-inquiries/reply', async (req, res) => {
  const { inquiry_id, message, sender } = req.body; // sender: 'admin' or 'tenant'
  if (!inquiry_id || !message || !sender) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }
  try {
    // Get the original inquiry to fetch unit_id and sender_name
    const [inquiryRows] = await db.execute(
      'SELECT unit_id, sender_name FROM unit_inquiries WHERE inquiry_id = ?',
      [inquiry_id]
    );
    if (inquiryRows.length === 0) {
      return res.status(404).json({ message: 'Inquiry not found.' });
    }
    const { unit_id, sender_name } = inquiryRows[0];
    // Insert reply as a new message
    await db.execute(
      'INSERT INTO unit_inquiries (unit_id, sender_name, message, sender) VALUES (?, ?, ?, ?)',
      [unit_id, sender_name, message, sender]
    );
    res.json({ message: 'Reply sent.' });
  } catch (err) {
    res.status(500).json({ message: 'Database error.' });
  }
});
