const express = require('express');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

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
    port: process.env.DB_PORT,
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
    const { fullName, email, username, password } = req.body;

    if (!fullName || !email || !username || !password) {
        return res.status(400).json({ message: 'Full Name, Email, Username, and Password are required.' });
    }

    try {
        const [existingAdmin] = await db.execute('SELECT * FROM admins WHERE username = ?', [username]);
        if (existingAdmin.length > 0) {
            return res.status(409).json({ message: 'Username already exists for an admin account.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.execute(
            'INSERT INTO admins (full_name, email, username, password) VALUES (?, ?, ?, ?)',
            [fullName, email, username, hashedPassword]
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
        const [admins] = await db.execute('SELECT * FROM admins WHERE username = ?', [username]);

        if (admins.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const admin = admins[0];
        const passwordMatch = await bcrypt.compare(password, admin.password);

        if (passwordMatch) {
            res.status(200).json({ message: 'Admin login successful!' });
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
        const [existingUser] = await db.execute('SELECT * FROM tenants WHERE username = ?', [username]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.execute(
            'INSERT INTO tenants (username, password, full_name, email, contact_number, apartment_id, emergency_contact, emergency_contact_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber]
        );

        res.status(201).json({ message: 'Tenant registered successfully', tenantId: result.insertId });
    } catch (error) {
        console.error('Error during registration:', error);
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

        // Send OTP to email if available
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

app.post('/api/tenant/submit-complaint', async (req, res) => {
    const { tenantId, complaint, date } = req.body;

    if (!tenantId || !complaint || !date) {
        return res.status(400).json({ message: 'Tenant ID, complaint, and date are required' });
    }

    try {
        await db.execute(
            'INSERT INTO tenant_complaints (tenant_id, complaint_text, complaint_date, status, admin_message) VALUES (?, ?, ?, ?, ?)',
            [tenantId, complaint, date, 'Pending', null]
        );
        res.status(201).json({ message: 'Complaint submitted successfully' });
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
        res.status(200).json(complaints);
    } catch (error) {
        console.error('Error fetching tenant complaints:', error);
        handleDatabaseError(res, error);
    }
});

app.put('/api/tenant/complaints/:complaintId', async (req, res) => {
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
        res.status(200).json({ message: 'Complaint updated successfully.' });
    } catch (error) {
        console.error('Error updating tenant complaint:', error);
        handleDatabaseError(res, error);
    }
});

// Delete a tenant complaint by ID
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
            'WHERE tc.status IS NULL OR tc.status = "Pending" ' +
            'ORDER BY tc.submitted_at DESC'
        );
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
            'WHERE tc.status = "Attended" OR tc.status = "Declined" ' +
            'ORDER BY tc.submitted_at DESC'
        );
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
            res.status(404).json({ message: `Complaint ${complaintId} not found or no changes made.` });
        }
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('Error updating complaint status by admin:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/tenant/submit-visitor', async (req, res) => {
    const { tenantId, fullName, apartmentId, visitorNames, visitDate, timeIn } = req.body;

    if (!tenantId || !fullName || !apartmentId || !visitorNames || !visitDate || !timeIn) {
        return res.status(400).json({ message: 'All visitor log fields are required.' });
    }

    try {
        const [result] = await db.execute(
            'INSERT INTO visitor_logs (tenant_id, apartment_id, unit_owner_name, visitor_names, visit_date, time_in) VALUES (?, ?, ?, ?, ?, ?)',
            [tenantId, apartmentId, fullName, visitorNames, visitDate, timeIn]
        );
        res.status(201).json({ message: 'Visitor log submitted successfully!', logId: result.insertId });
    } catch (error) {
        console.error('Error submitting visitor log:', error);
        handleDatabaseError(res, error);
    }
});

app.get('/api/admin/visitor-logs', async (req, res) => {
    try {
        const [visitorLogs] = await db.execute(
            'SELECT log_id, tenant_id, apartment_id, unit_owner_name, visitor_names, visit_date, time_in, created_at ' +
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

app.put('/api/tenant/profile/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    const { fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber, currentPassword, newPassword } = req.body;

    if (!fullName || !contactNumber || !apartmentId) {
        return res.status(400).json({ message: 'Full Name, Contact Number, and Apartment ID are required.' });
    }

    try {
        let updateQuery = 'UPDATE tenants SET full_name = ?, email = ?, contact_number = ?, apartment_id = ?, emergency_contact = ?, emergency_contact_number = ?';
        let queryParams = [fullName, email, contactNumber, apartmentId, emergencyContact, emergencyContactNumber];

        if (newPassword) {
            const [tenants] = await db.execute('SELECT password FROM tenants WHERE tenant_id = ?', [tenantId]);
            if (tenants.length === 0) {
                return res.status(404).json({ message: 'Tenant not found.' });
            }
            const storedHashedPassword = tenants[0].password;

            const passwordMatch = await bcrypt.compare(currentPassword, storedHashedPassword);
            if (!passwordMatch) {
                return res.status(401).json({ message: 'Invalid current password.' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);
            updateQuery += ', password = ?';
            queryParams.push(hashedPassword);
        }

        updateQuery += ' WHERE tenant_id = ?';
        queryParams.push(tenantId);

        const [result] = await db.execute(updateQuery, queryParams);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Tenant not found or no changes made.' });
        }

        res.status(200).json({ message: 'Account updated successfully!' });
    } catch (error) {
        console.error('Error updating tenant profile:', error);
        handleDatabaseError(res, error);
    }
});

app.post('/api/admin/forgot-password/verify-token', async (req, res) => {
    const { developerToken } = req.body;

    if (!developerToken) {
        return res.status(400).json({ message: 'Developer token is required.' });
    }

    if (developerToken === DEVELOPER_TOKEN) {
        res.status(200).json({ message: 'Developer token verified successfully.' });
    } else {
        res.status(401).json({ message: 'Invalid developer token.' });
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

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
