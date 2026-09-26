# Hosting Guide for Unity Credit Union

## Email Configuration for Production

The application uses Flask-Mail for sending emails. Here's how to configure it properly for production:

### 1. Current Email Setup

The application is configured to use your existing mail server:
- **Server**: mail.raydexhub.com
- **Port**: 465 (SSL)
- **Protocol**: SSL (not TLS)

### 2. Required Environment Variables

Update your `.env` file with your actual email credentials:

```env
# Email Configuration
MAIL_SERVER=mail.raydexhub.com
MAIL_PORT=465
MAIL_USE_SSL=1
MAIL_USE_TLS=0
MAIL_USERNAME=your_email@raydexhub.com
MAIL_PASSWORD=your_email_password
```

### 3. Email Templates

The application includes these email templates:
- `account_created.html` - New account registration
- `account_verified.html` - Account verification
- `guarantor_notice.html` - Guarantor notification for loans
- `loan_received.html` - Loan application received
- `loan_approved.html` - Loan approval notification
- `loan_rejected.html` - Loan rejection notification
- `password_reset_request.html` - Password reset request
- `admin_new_loan.html` - Admin notification for new loans
- And many more...

### 4. Testing Email Configuration

Before deploying to production, test your email setup:

```python
# Create a test script: test_email.py
from app import create_app
from flask_mail import Message
from extensions import mail

app = create_app()

with app.app_context():
    msg = Message(
        subject="Test Email from UCU",
        recipients=["agyareemmanuelosei@gmail.com"],
        html="<h1>Test Email</h1><p>This is a test email from Unity Credit Union.</p>"
    )
    try:
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Email failed: {e}")
```

Run it with: `python test_email.py`

### 5. Common Email Issues and Solutions

#### Issue: Authentication Failed
- **Solution**: Verify MAIL_USERNAME and MAIL_PASSWORD are correct
- Check if your mail server requires SSL/TLS authentication
- Ensure the email account has sending permissions

#### Issue: Connection Timeout
- **Solution**: Check if port 465 is accessible from your hosting environment
- Some hosting providers block SMTP ports - you may need to use their relay service

#### Issue: SSL Certificate Error
- **Solution**: Some self-signed certificates cause issues
- Try setting `MAIL_USE_SSL=0` and `MAIL_USE_TLS=1` with port 587

### 6. Alternative Email Services

If your current mail server doesn't work reliably, consider these alternatives:

#### Gmail (Less Secure Apps - Deprecated)
- Google has disabled less secure apps
- Use App Passwords instead: https://support.google.com/accounts/answer/185833

#### SendGrid
```env
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USE_TLS=1
MAIL_USERNAME=apikey
MAIL_PASSWORD=SG.your_sendgrid_api_key
```

#### Mailgun
```env
MAIL_SERVER=smtp.mailgun.org
MAIL_PORT=587
MAIL_USE_TLS=1
MAIL_USERNAME=postmaster@your_domain.com
MAIL_PASSWORD=your_mailgun_password
```

#### AWS SES
```env
MAIL_SERVER=email-smtp.us-east-1.amazonaws.com
MAIL_PORT=587
MAIL_USE_TLS=1
MAIL_USERNAME=your_aws_access_key
MAIL_PASSWORD=your_aws_secret_key
```

### 7. Production Security Settings

Update your `.env` for production:

```env
# Generate a secure secret key
SECRET_KEY=generate_with_python_secrets_module

# Enable HTTPS
FORCE_HTTPS=1

# Update site URL
SITE_URL=https://ucu.raydexhub.com
```

### 8. Email Delivery Best Practices

1. **SPF Records**: Add SPF records to your domain DNS
   ```
   v=spf1 include:raydexhub.com ~all
   ```

2. **DKIM**: Set up DKIM authentication for better deliverability

3. **DMARC**: Configure DMARC policies to prevent email spoofing

4. **Monitoring**: Monitor email delivery rates and bounce handling

### 9. Hosting Environment Checklist

- [ ] Email credentials configured in `.env`
- [ ] Email sending tested successfully
- [ ] SPF/DKIM/DMARC records configured
- [ ] Firewall allows SMTP port (465 or 587)
- [ ] Application logs monitored for email errors
- [ ] Backup email service configured (optional)
- [ ] Email templates reviewed for production content
- [ ] Admin email set to receive notifications

### 10. Troubleshooting Email Issues

Check the application logs for email-related errors:
```bash
# If using Flask development server
# Check console output for email errors

# If using production server (gunicorn)
tail -f /var/log/ucu/app.log | grep -i email
```

Common log messages:
- "Could not send e-mail to [recipient]: [error]" - Email delivery failed
- "E-mail not sent to [recipient]: MAIL_USERNAME is not set" - Configuration missing
- "MAIL_ASYNC" related errors - Threading issues (set MAIL_ASYNC=0 for debugging)

### 11. Email Functionality in Your Application

The guarantor form will trigger these emails:
1. **Loan Application Received** - Sent to applicant
2. **Guarantor Notice** - Sent to both guarantors
3. **Admin Notification** - Sent to admin email

All emails are sent asynchronously to prevent slowing down the application.

## Database Configuration

### SQLite (Development/Small Deployments)

By default, the application uses SQLite stored in `instance/credit_union.db`. This is suitable for:
- Development and testing
- Small-scale deployments with low traffic
- Single-user or small team usage

### MySQL (Production Recommended)

For production hosting, MySQL is recommended for better performance, concurrent access, and data integrity.

#### 1. Install MySQL

On your hosting server:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation

# CentOS/RHEL
sudo yum install mysql-server
sudo systemctl start mysqld
sudo mysql_secure_installation
```

#### 2. Create Database and User

```sql
-- Connect to MySQL
mysql -u root -p

-- Create database
CREATE DATABASE ucu_production CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user with strong password
CREATE USER 'ucu_user'@'localhost' IDENTIFIED BY 'strong_secure_password_here';

-- Grant privileges
GRANT ALL PRIVILEGES ON ucu_production.* TO 'ucu_user'@'localhost';

-- Flush privileges and exit
FLUSH PRIVILEGES;
EXIT;
```

#### 3. Configure Environment Variables

Update your `.env` file with MySQL connection details:

```env
# MySQL Database Configuration
DATABASE_URL=mysql://ucu_user:strong_secure_password_here@localhost/ucu_production
```

The application will automatically convert this to `mysql+pymysql://` for SQLAlchemy.

#### 4. Install PyMySQL

The application is already configured to use PyMySQL for MySQL connections. Ensure it's installed:

```bash
pip install pymysql
```

It's already included in `requirements.txt`.

#### 5. Run Migrations

After configuring MySQL, run the migrations:

```bash
flask db upgrade
```

This will create all necessary tables in your MySQL database.

#### 6. MySQL Connection Pool Configuration

The application uses SQLAlchemy's connection pooling for MySQL:
- `pool_pre_ping: True` - Automatically checks connection health
- Default pool size is 5 (suitable for most applications)
- For high-traffic sites, you may need to tune this in `config.py`

### Database Backup Strategy

#### SQLite Backup
```bash
# Simple file copy
cp instance/credit_union.db backups/credit_union_$(date +%Y%m%d).db

# Or use SQLite backup command
sqlite3 instance/credit_union.db ".backup backups/credit_union_$(date +%Y%m%d).db"
```

#### MySQL Backup
```bash
# Full database backup
mysqldump -u ucu_user -p ucu_production > backups/ucu_$(date +%Y%m%d).sql

# Compressed backup
mysqldump -u ucu_user -p ucu_production | gzip > backups/ucu_$(date +%Y%m%d).sql.gz

# Automated daily backup (add to crontab)
0 2 * * * mysqldump -u ucu_user -pPASSWORD ucu_production | gzip > /backups/ucu_$(date +\%Y\%m\%d).sql.gz
```

### Database Migration

Don't forget to run database migrations before deploying:
```bash
flask db upgrade
```

## Security Notes

- Never commit `.env` file to version control
- Use strong, unique passwords for email accounts
- Rotate email passwords regularly
- Monitor for unauthorized email sending
- Consider implementing rate limiting for email sending
