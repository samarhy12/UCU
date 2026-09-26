# Hosting Checklist for Unity Credit Union

## Pre-Hosting Checklist

### 1. Email Configuration
- [ ] Update `.env` file with email credentials:
  ```
  MAIL_USERNAME=your_email@raydexhub.com
  MAIL_PASSWORD=your_email_password
  ```
- [ ] Run email test: `python test_email.py`
- [ ] Verify test email received
- [ ] Check application logs for email errors

### 2. Security Configuration
- [ ] Generate secure SECRET_KEY:
  ```python
  import secrets
  print(secrets.token_hex(32))
  ```
- [ ] Update SECRET_KEY in `.env`
- [ ] Set FORCE_HTTPS=1 when using HTTPS
- [ ] Ensure SESSION_COOKIE_SECURE is enabled in production

### 3. Database Setup
- [ ] Choose database: SQLite (small scale) or MySQL (production recommended)
- [ ] If using MySQL:
  - [ ] Install MySQL server
  - [ ] Create database and user
  - [ ] Set DATABASE_URL in `.env`: `mysql://username:password@host/database`
  - [ ] Verify PyMySQL is installed
- [ ] Run database migrations: `flask db upgrade`
- [ ] Verify database connection
- [ ] Backup existing database if upgrading
- [ ] Test database operations
- [ ] Set up automated backups

### 4. File Uploads Configuration
- [ ] Ensure upload directories exist:
  - `uploads/`
  - `static/uploads/executives/`
  - `static/uploads/adverts/`
  - `static/uploads/gallery/`
  - `static/uploads/carousel/`
  - `static/uploads/greeting/`
- [ ] Set proper permissions on upload directories
- [ ] Configure max upload sizes if needed

### 5. Contact Information
- [ ] Verify CONTACT_EMAIL is correct
- [ ] Verify CONTACT_PHONE is correct
- [ ] Verify WHATSAPP_URL is correct
- [ ] Update SOCIAL_MEDIA links if needed

### 6. Site Configuration
- [ ] Set correct SITE_URL
- [ ] Update ORG_ADDRESS if needed
- [ ] Verify ORG_NAME and ORG_SHORT

## Hosting Environment Setup

### 7. Server Requirements
- [ ] Python 3.8+ installed
- [ ] Virtual environment created
- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Database backup/restore procedures in place

### 8. Web Server Configuration
- [ ] Configure Nginx/Apache for Flask app
- [ ] Set up SSL certificate (Let's Encrypt recommended)
- [ ] Configure reverse proxy
- [ ] Set up static file serving
- [ ] Configure WSGI server (Gunicorn recommended)

### 9. Firewall Configuration
- [ ] Allow HTTP (port 80)
- [ ] Allow HTTPS (port 443)
- [ ] Allow SMTP port (465 or 587) for email
- [ ] Restrict other ports as needed

### 10. Monitoring Setup
- [ ] Set up application logging
- [ ] Configure log rotation
- [ ] Set up error monitoring
- [ ] Configure uptime monitoring
- [ ] Set up backup monitoring

## Post-Hosting Verification

### 11. Functionality Testing
- [ ] Test user registration
- [ ] Test email verification
- [ ] Test loan application
- [ ] Test guarantor form download
- [ ] Test password reset
- [ ] Test contact form
- [ ] Test admin panel access

### 12. Email Testing
- [ ] Test registration email
- [ ] Test loan application email
- [ ] Test guarantor notification email
- [ ] Test admin notification email
- [ ] Check spam folders
- [ ] Verify email deliverability

### 13. Performance Testing
- [ ] Test page load times
- [ ] Test form submission speed
- [ ] Test file upload performance
- [ ] Test database query performance
- [ ] Monitor memory usage

### 14. Security Testing
- [ ] Test SQL injection protection
- [ ] Test XSS protection
- [ ] Test CSRF protection
- [ ] Test session security
- [ ] Test file upload security
- [ ] Test rate limiting

## Ongoing Maintenance

### 15. Backup Strategy
- [ ] Daily database backups
- [ ] Weekly file backups
- [ ] Off-site backup storage
- [ ] Backup restoration testing
- [ ] Backup retention policy

### 16. Update Management
- [ ] Security update monitoring
- [ ] Dependency update process
- [ ] Testing procedure for updates
- [ ] Rollback plan
- [ ] Maintenance window schedule

### 17. Monitoring Alerts
- [ ] Server uptime alerts
- [ ] Email delivery failure alerts
- [ ] Error rate alerts
- [ ] Disk space alerts
- [ ] Performance degradation alerts

## Emergency Procedures

### 18. Disaster Recovery
- [ ] Documented recovery procedures
- [ ] Emergency contact list
- [ ] Backup restoration steps
- [ ] Alternative email service configured
- [ ] Customer communication plan

## Specific Guarantor Form Features

### 19. Guarantor Form Testing
- [ ] Test "Print/Save guarantor form" button
- [ ] Verify popup window opens correctly
- [ ] Test print dialog appears
- [ ] Test PDF generation works
- [ ] Verify guarantor acknowledgment checkboxes
- [ ] Test email notification to guarantors

### 20. Email Templates Review
- [ ] Review guarantor_notice.html content
- [ ] Verify loan_received.html content
- [ ] Check admin_new_loan.html content
- [ ] Ensure all templates have correct branding
- [ ] Verify contact information in templates

## Troubleshooting Quick Reference

### Email Issues
- **No emails sent**: Check MAIL_USERNAME and MAIL_PASSWORD
- **Authentication failed**: Verify email credentials
- **Connection timeout**: Check firewall and port accessibility
- **Spam folder issues**: Configure SPF/DKIM/DMARC records

### Database Issues
- **Migration errors**: Check database permissions
- **Connection errors**: Verify DATABASE_URL
- **Performance issues**: Index optimization

### File Upload Issues
- **Upload fails**: Check directory permissions
- **Size limit exceeded**: Adjust MAX_UPLOAD_MB
- **File type rejected**: Check ALLOWED_IMAGE_EXTENSIONS

## Contact Information for Support

- **Technical Support**: [Your contact]
- **Email Support**: agyareemmanuelosei@gmail.com
- **Emergency Contact**: [Your emergency contact]

## Final Go-Live Checklist

- [ ] All configuration completed
- [ ] All tests passed
- [ ] Backup procedures verified
- [ ] Monitoring configured
- [ ] Team trained on procedures
- [ ] Rollback plan tested
- [ ] Support documentation updated
- [ ] Go-live scheduled
- [ ] Stakeholders notified
- [ ] SUCCESSFUL DEPLOYMENT! 🎉
