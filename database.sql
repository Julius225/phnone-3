CREATE DATABASE IF NOT EXISTS umoya_circle
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE umoya_circle;

CREATE TABLE IF NOT EXISTS members (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  member_number VARCHAR(20) NULL,
  full_name VARCHAR(160) NOT NULL,
  phone VARCHAR(20) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('Member', 'Treasurer', 'Secretary', 'Chairperson', 'Admin') NOT NULL DEFAULT 'Member',
  status ENUM('Active', 'Inactive') NOT NULL DEFAULT 'Active',
  profile_photo VARCHAR(255) NULL,
  registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_members_member_number (member_number),
  UNIQUE KEY uq_members_phone (phone),
  UNIQUE KEY uq_members_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS contributions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  member_id BIGINT UNSIGNED NOT NULL,
  recorded_by BIGINT UNSIGNED NOT NULL,
  amount DECIMAL(12, 2) NOT NULL,
  payment_method ENUM('Cash', 'Bank', 'Mobile money') NOT NULL,
  reference VARCHAR(100) NULL,
  status ENUM('Pending', 'Verified') NOT NULL DEFAULT 'Pending',
  paid_at DATE NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_contributions_member_date (member_id, paid_at),
  KEY idx_contributions_status (status),
  CONSTRAINT fk_contributions_member FOREIGN KEY (member_id) REFERENCES members (id),
  CONSTRAINT fk_contributions_recorder FOREIGN KEY (recorded_by) REFERENCES members (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS loans (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  member_id BIGINT UNSIGNED NOT NULL,
  requested_by BIGINT UNSIGNED NOT NULL,
  requested_amount DECIMAL(12, 2) NOT NULL,
  purpose VARCHAR(500) NOT NULL,
  requested_term_months SMALLINT UNSIGNED NULL,
  status ENUM('Pending', 'Approved', 'Rejected', 'Active', 'Paid') NOT NULL DEFAULT 'Pending',
  approved_amount DECIMAL(12, 2) NULL,
  total_due DECIMAL(12, 2) NULL,
  due_date DATE NULL,
  approved_by BIGINT UNSIGNED NULL,
  approved_at DATETIME NULL,
  disbursed_by BIGINT UNSIGNED NULL,
  disbursed_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_loans_member_status (member_id, status),
  KEY idx_loans_status_date (status, created_at),
  CONSTRAINT fk_loans_member FOREIGN KEY (member_id) REFERENCES members (id),
  CONSTRAINT fk_loans_requester FOREIGN KEY (requested_by) REFERENCES members (id),
  CONSTRAINT fk_loans_approver FOREIGN KEY (approved_by) REFERENCES members (id),
  CONSTRAINT fk_loans_disburser FOREIGN KEY (disbursed_by) REFERENCES members (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS loan_repayments (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  loan_id BIGINT UNSIGNED NOT NULL,
  member_id BIGINT UNSIGNED NOT NULL,
  recorded_by BIGINT UNSIGNED NOT NULL,
  amount DECIMAL(12, 2) NOT NULL,
  payment_method ENUM('Cash', 'Bank', 'Mobile money') NOT NULL,
  reference VARCHAR(100) NULL,
  status ENUM('Pending', 'Verified') NOT NULL DEFAULT 'Pending',
  paid_at DATE NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_loan_repayments_loan_status (loan_id, status),
  KEY idx_loan_repayments_member_date (member_id, paid_at),
  CONSTRAINT fk_loan_repayments_loan FOREIGN KEY (loan_id) REFERENCES loans (id),
  CONSTRAINT fk_loan_repayments_member FOREIGN KEY (member_id) REFERENCES members (id),
  CONSTRAINT fk_loan_repayments_recorder FOREIGN KEY (recorded_by) REFERENCES members (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS meetings (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  title VARCHAR(160) NOT NULL,
  description VARCHAR(2000) NULL,
  location VARCHAR(200) NOT NULL,
  starts_at DATETIME NOT NULL,
  status ENUM('Scheduled', 'Completed', 'Cancelled') NOT NULL DEFAULT 'Scheduled',
  created_by BIGINT UNSIGNED NOT NULL,
  status_updated_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_meetings_schedule (starts_at, status),
  CONSTRAINT fk_meetings_creator FOREIGN KEY (created_by) REFERENCES members (id),
  CONSTRAINT fk_meetings_status_user FOREIGN KEY (status_updated_by) REFERENCES members (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS attendance_records (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  meeting_id BIGINT UNSIGNED NOT NULL,
  member_id BIGINT UNSIGNED NOT NULL,
  attendance_status ENUM('Present', 'Absent', 'Apology') NOT NULL,
  recorded_by BIGINT UNSIGNED NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_attendance_meeting_member (meeting_id, member_id),
  KEY idx_attendance_member_date (member_id, updated_at),
  CONSTRAINT fk_attendance_meeting FOREIGN KEY (meeting_id) REFERENCES meetings (id),
  CONSTRAINT fk_attendance_member FOREIGN KEY (member_id) REFERENCES members (id),
  CONSTRAINT fk_attendance_recorder FOREIGN KEY (recorded_by) REFERENCES members (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS meeting_minutes (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  meeting_id BIGINT UNSIGNED NOT NULL,
  title VARCHAR(160) NOT NULL,
  content MEDIUMTEXT NOT NULL,
  status ENUM('Draft', 'Published') NOT NULL DEFAULT 'Draft',
  created_by BIGINT UNSIGNED NOT NULL,
  updated_by BIGINT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_meeting_minutes_meeting (meeting_id),
  KEY idx_meeting_minutes_status (status, updated_at),
  CONSTRAINT fk_meeting_minutes_meeting FOREIGN KEY (meeting_id) REFERENCES meetings (id),
  CONSTRAINT fk_meeting_minutes_creator FOREIGN KEY (created_by) REFERENCES members (id),
  CONSTRAINT fk_meeting_minutes_updater FOREIGN KEY (updated_by) REFERENCES members (id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS expenses (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  payee VARCHAR(160) NOT NULL,
  category VARCHAR(100) NOT NULL,
  description VARCHAR(500) NULL,
  amount DECIMAL(12, 2) NOT NULL,
  reference VARCHAR(100) NULL,
  expense_date DATE NOT NULL,
  status ENUM('Pending', 'Verified') NOT NULL DEFAULT 'Pending',
  recorded_by BIGINT UNSIGNED NOT NULL,
  verified_by BIGINT UNSIGNED NULL,
  verified_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_expenses_date_status (expense_date, status),
  CONSTRAINT fk_expenses_recorder FOREIGN KEY (recorded_by) REFERENCES members (id),
  CONSTRAINT fk_expenses_verifier FOREIGN KEY (verified_by) REFERENCES members (id)
) ENGINE=InnoDB;

