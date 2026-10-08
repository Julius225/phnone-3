<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Strict',
    'path' => '/',
]);
session_start();

function respond(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function request_data(): array
{
    $data = json_decode(file_get_contents('php://input'), true);
    if (!is_array($data)) {
        respond(400, ['error' => 'Send a valid JSON request.']);
    }
    return $data;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function require_csrf(array $data): void
{
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($data['csrf_token'] ?? '');
    if (!is_string($provided) || !hash_equals(csrf_token(), $provided)) {
        respond(403, ['error' => 'Your session expired. Refresh the page and try again.']);
    }
}

function public_member(array $member): array
{
    return [
        'member_number' => $member['member_number'],
        'full_name' => $member['full_name'],
        'phone' => $member['phone'],
        'email' => $member['email'],
        'role' => $member['role'],
        'status' => $member['status'],
        'registered_at' => $member['registered_at'],
    ];
}

function current_member(PDO $db): ?array
{
    if (empty($_SESSION['member_id'])) {
        return null;
    }
    $query = $db->prepare('SELECT * FROM members WHERE id = :id LIMIT 1');
    $query->execute(['id' => $_SESSION['member_id']]);
    $member = $query->fetch(PDO::FETCH_ASSOC);
    if (!$member || $member['status'] !== 'Active') {
        unset($_SESSION['member_id']);
        return null;
    }
    return $member;
}

function finish_login(array $member): void
{
    session_regenerate_id(true);
    $_SESSION['member_id'] = $member['id'];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    respond(200, ['member' => public_member($member), 'csrf_token' => csrf_token()]);
}

try {
    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $name = getenv('DB_NAME') ?: 'umoya_circle';
    $user = getenv('DB_USER') ?: 'root';
    $password = getenv('DB_PASSWORD') ?: '';
    $db = new PDO(
        "mysql:host={$host};dbname={$name};charset=utf8mb4",
        $user,
        $password,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );

    $action = $_GET['action'] ?? '';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($action === 'me' && $method === 'GET') {
        $member = current_member($db);
        respond(200, [
            'member' => $member ? public_member($member) : null,
            'csrf_token' => csrf_token(),
        ]);
    }

    if ($action === 'register' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $fullName = trim((string)($data['full_name'] ?? ''));
        $phone = preg_replace('/[\s()-]/', '', trim((string)($data['phone'] ?? '')));
        $email = strtolower(trim((string)($data['email'] ?? '')));
        $plainPassword = (string)($data['password'] ?? '');

        if (strlen($fullName) < 2 || strlen($fullName) > 160) {
            respond(422, ['error' => 'Enter your full name (2 to 160 characters).']);
        }
        if (preg_match('/[<>]/', $fullName)) {
            respond(422, ['error' => 'Names cannot contain angle brackets.']);
        }
        if (!preg_match('/^\+?[0-9]{8,15}$/', $phone)) {
            respond(422, ['error' => 'Enter a valid phone number, including country code if needed.']);
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
            respond(422, ['error' => 'Enter a valid email address.']);
        }
        if (strlen($plainPassword) < 10 || strlen($plainPassword) > 200) {
            respond(422, ['error' => 'Use a password between 10 and 200 characters.']);
        }

        $db->beginTransaction();
        $insert = $db->prepare(
            'INSERT INTO members (full_name, phone, email, password_hash) VALUES (:name, :phone, :email, :password)'
        );
        $insert->execute([
            'name' => $fullName,
            'phone' => $phone,
            'email' => $email,
            'password' => password_hash($plainPassword, PASSWORD_DEFAULT),
        ]);
        $id = (int)$db->lastInsertId();
        $memberNumber = 'UM-' . str_pad((string)$id, 5, '0', STR_PAD_LEFT);
        $update = $db->prepare('UPDATE members SET member_number = :number WHERE id = :id');
        $update->execute(['number' => $memberNumber, 'id' => $id]);
        $db->commit();

        $query = $db->prepare('SELECT * FROM members WHERE id = :id');
        $query->execute(['id' => $id]);
        finish_login($query->fetch());
    }

    if ($action === 'login' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $identifier = trim((string)($data['identifier'] ?? ''));
        $email = strtolower($identifier);
        $phone = preg_replace('/[\s()-]/', '', $identifier);
        $query = $db->prepare('SELECT * FROM members WHERE email = :email OR phone = :phone LIMIT 1');
        $query->execute(['email' => $email, 'phone' => $phone]);
        $member = $query->fetch();
        if (!$member || $member['status'] !== 'Active' || !password_verify((string)($data['password'] ?? ''), $member['password_hash'])) {
            respond(401, ['error' => 'Email, phone, or password is incorrect, or the account is inactive.']);
        }
        finish_login($member);
    }

    if ($action === 'logout' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'] ?? '', $params['secure'], $params['httponly']);
        }
        session_destroy();
        respond(200, ['member' => null]);
    }

    if ($action === 'contributions' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view contributions.']);
        }
           $canViewAllRecords = in_array($member['role'], ['Admin', 'Treasurer'], true);
           $canViewGroupSummary = $canViewAllRecords || $member['role'] === 'Chairperson';
           $recordScope = $canViewAllRecords ? '' : ' WHERE c.member_id = :member_id';
        $query = $db->prepare(
            'SELECT c.id, m.member_number, m.full_name, c.amount, c.payment_method, c.reference, c.status, c.paid_at
               FROM contributions c JOIN members m ON m.id = c.member_id' . $recordScope . ' ORDER BY c.created_at DESC, c.id DESC'
        );
           $query->execute($canViewAllRecords ? [] : ['member_id' => $member['id']]);
        $records = array_map(static function (array $record): array {
            $record['receipt_number'] = 'RCPT-' . str_pad((string)$record['id'], 6, '0', STR_PAD_LEFT);
            unset($record['id']);
            return $record;
        }, $query->fetchAll());
        $summaryQuery = $db->prepare(
            'SELECT
                COALESCE(SUM(CASE WHEN c.status = \'Verified\' THEN c.amount ELSE 0 END), 0) AS total_verified,
                COALESCE(SUM(CASE WHEN c.status = \'Pending\' THEN c.amount ELSE 0 END), 0) AS total_pending,
                COALESCE(SUM(CASE WHEN c.status = \'Verified\' AND YEAR(c.paid_at) = YEAR(CURDATE()) AND MONTH(c.paid_at) = MONTH(CURDATE()) THEN c.amount ELSE 0 END), 0) AS current_month_verified,
                COALESCE(SUM(CASE WHEN c.status = \'Pending\' AND YEAR(c.paid_at) = YEAR(CURDATE()) AND MONTH(c.paid_at) = MONTH(CURDATE()) THEN c.amount ELSE 0 END), 0) AS current_month_pending
               FROM contributions c' . ($canViewGroupSummary ? '' : ' WHERE c.member_id = :member_id')
        );
           $summaryQuery->execute($canViewGroupSummary ? [] : ['member_id' => $member['id']]);
        $summary = $summaryQuery->fetch();
        $memberTotals = $db->prepare(
            'SELECT
                COALESCE(SUM(CASE WHEN status = \'Verified\' THEN amount ELSE 0 END), 0) AS member_total_verified,
                COALESCE(SUM(CASE WHEN status = \'Pending\' THEN amount ELSE 0 END), 0) AS member_total_pending
             FROM contributions WHERE member_id = :member_id'
        );
        $memberTotals->execute(['member_id' => $member['id']]);
        $summary = array_merge($summary, $memberTotals->fetch());
        $summary['members_contributed_current_month'] = null;
        $summary['members_not_contributed_current_month'] = null;
        if ($canViewGroupSummary) {
            $memberCounts = $db->query(
                "SELECT COUNT(DISTINCT m.id) AS member_count,
                    COUNT(DISTINCT CASE WHEN c.id IS NOT NULL THEN m.id END) AS contributed_count
                 FROM members m
                 LEFT JOIN contributions c ON c.member_id = m.id
                    AND c.status = 'Verified'
                    AND c.paid_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')
                    AND c.paid_at < DATE_FORMAT(CURDATE() + INTERVAL 1 MONTH, '%Y-%m-01')
                 WHERE m.status = 'Active'"
            )->fetch();
            $summary['members_contributed_current_month'] = (int)$memberCounts['contributed_count'];
            $summary['members_not_contributed_current_month'] = max(0, (int)$memberCounts['member_count'] - (int)$memberCounts['contributed_count']);
        }
        respond(200, ['contributions' => $records, 'summary' => $summary]);
    }

    if ($action === 'contribution' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to record a contribution.']);
        }
        $canRecordForOthers = in_array($member['role'], ['Admin', 'Treasurer'], true);
        $memberNumber = $canRecordForOthers ? trim((string)($data['member_number'] ?? '')) : $member['member_number'];
        $amount = trim((string)($data['amount'] ?? ''));
        $methodValue = (string)($data['payment_method'] ?? '');
        $reference = trim((string)($data['reference'] ?? ''));
        $paidAt = (string)($data['paid_at'] ?? '');

        if (!preg_match('/^\d{1,10}(?:\.\d{1,2})?$/', $amount) || (float)$amount <= 0) {
            respond(422, ['error' => 'Enter a contribution amount greater than zero.']);
        }
        if (!in_array($methodValue, ['Cash', 'Bank', 'Mobile money'], true)) {
            respond(422, ['error' => 'Choose a valid payment method.']);
        }
        if ($methodValue === 'Mobile money' && $reference === '') {
            respond(422, ['error' => 'Enter the M-Pesa or mobile money reference.']);
        }
        $date = DateTime::createFromFormat('!Y-m-d', $paidAt);
        if (!$date || $date->format('Y-m-d') !== $paidAt) {
            respond(422, ['error' => 'Choose a valid payment date.']);
        }
        if (strlen($reference) > 100) {
            respond(422, ['error' => 'Payment references must be 100 characters or fewer.']);
        }
        if ($methodValue === 'Mobile money' && strlen($reference) > 50) {
            respond(422, ['error' => 'Mobile money references must be 50 characters or fewer.']);
        }
        $findMember = $db->prepare('SELECT id FROM members WHERE member_number = :number');
        $findMember->execute(['number' => $memberNumber]);
        $target = $findMember->fetch();
        if (!$target) {
            respond(404, ['error' => 'Choose an existing member.']);
        }
        $status = 'Pending';
        $insert = $db->prepare(
            'INSERT INTO contributions (member_id, recorded_by, amount, payment_method, reference, status, paid_at)
             VALUES (:member_id, :recorded_by, :amount, :method, :reference, :status, :paid_at)'
        );
        $insert->execute([
            'member_id' => $target['id'],
            'recorded_by' => $member['id'],
            'amount' => $amount,
            'method' => $methodValue,
            'reference' => $reference !== '' ? $reference : null,
            'status' => $status,
            'paid_at' => $paidAt,
        ]);
        respond(201, [
            'message' => 'Contribution recorded and is pending verification.',
            'receipt_number' => 'RCPT-' . str_pad((string)$db->lastInsertId(), 6, '0', STR_PAD_LEFT),
            'status' => $status,
        ]);
    }

    if ($action === 'verify-contribution' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || !in_array($member['role'], ['Admin', 'Treasurer'], true)) {
            respond(403, ['error' => 'Only a treasurer or administrator can verify contributions.']);
        }
        $receiptNumber = (string)($data['receipt_number'] ?? '');
        if (!preg_match('/^RCPT-(\d{6,})$/', $receiptNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid contribution receipt.']);
        }
        $update = $db->prepare("UPDATE contributions SET status = 'Verified' WHERE id = :id AND status = 'Pending'");
        $update->execute(['id' => (int)$matches[1]]);
        if (!$update->rowCount()) {
            respond(404, ['error' => 'Pending contribution not found.']);
        }
        respond(200, ['message' => 'Contribution verified.']);
    }

    if ($action === 'loans' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view loans.']);
        }
        $canViewAll = in_array($member['role'], ['Admin', 'Treasurer', 'Chairperson'], true);
        $scope = $canViewAll ? '' : ' WHERE l.member_id = :member_id';
        $query = $db->prepare(
            'SELECT l.id, l.requested_amount, l.purpose, l.requested_term_months, l.status,
                    l.approved_amount, l.total_due, l.due_date, l.created_at, l.approved_at, l.disbursed_at,
                    m.member_number, m.full_name,
                    COALESCE(r.verified_total, 0) AS repaid_verified,
                    COALESCE(r.pending_total, 0) AS repaid_pending,
                    GREATEST(COALESCE(l.total_due, 0) - COALESCE(r.verified_total, 0), 0) AS outstanding
             FROM loans l
             JOIN members m ON m.id = l.member_id
             LEFT JOIN (
                SELECT loan_id,
                    SUM(CASE WHEN status = \'Verified\' THEN amount ELSE 0 END) AS verified_total,
                    SUM(CASE WHEN status = \'Pending\' THEN amount ELSE 0 END) AS pending_total
                FROM loan_repayments GROUP BY loan_id
             ) r ON r.loan_id = l.id' . $scope . ' ORDER BY l.created_at DESC, l.id DESC'
        );
        $query->execute($canViewAll ? [] : ['member_id' => $member['id']]);
        $loans = array_map(static function (array $loan): array {
            $loan['loan_number'] = 'LN-' . str_pad((string)$loan['id'], 6, '0', STR_PAD_LEFT);
            unset($loan['id']);
            return $loan;
        }, $query->fetchAll());
        $summary = $db->prepare(
            'SELECT COUNT(*) AS total_loans,
                    SUM(CASE WHEN status = \'Pending\' THEN 1 ELSE 0 END) AS pending_applications,
                    SUM(CASE WHEN status = \'Active\' THEN 1 ELSE 0 END) AS active_loans
             FROM loans' . ($canViewAll ? '' : ' WHERE member_id = :member_id')
        );
        $summary->execute($canViewAll ? [] : ['member_id' => $member['id']]);
        respond(200, ['loans' => $loans, 'summary' => $summary->fetch()]);
    }

    if ($action === 'loan-application' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to apply for a loan.']);
        }
        $amount = trim((string)($data['requested_amount'] ?? ''));
        $purpose = trim((string)($data['purpose'] ?? ''));
        $term = trim((string)($data['requested_term_months'] ?? ''));
        if (!preg_match('/^\d{1,10}(?:\.\d{1,2})?$/', $amount) || (float)$amount <= 0) {
            respond(422, ['error' => 'Enter a requested amount greater than zero.']);
        }
        if ($purpose === '' || mb_strlen($purpose) > 500) {
            respond(422, ['error' => 'Enter a purpose of 1 to 500 characters.']);
        }
        if ($term !== '' && (!ctype_digit($term) || (int)$term < 1 || (int)$term > 120)) {
            respond(422, ['error' => 'The requested term must be between 1 and 120 months.']);
        }
        $insert = $db->prepare(
            'INSERT INTO loans (member_id, requested_by, requested_amount, purpose, requested_term_months)
             VALUES (:member_id, :requested_by, :amount, :purpose, :term)'
        );
        $insert->execute([
            'member_id' => $member['id'],
            'requested_by' => $member['id'],
            'amount' => $amount,
            'purpose' => $purpose,
            'term' => $term !== '' ? (int)$term : null,
        ]);
        respond(201, [
            'message' => 'Loan application submitted for approval.',
            'loan_number' => 'LN-' . str_pad((string)$db->lastInsertId(), 6, '0', STR_PAD_LEFT),
            'status' => 'Pending',
        ]);
    }

    if ($action === 'loan-decision' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || !in_array($member['role'], ['Admin', 'Chairperson'], true)) {
            respond(403, ['error' => 'Only an administrator or chairperson can approve loan applications.']);
        }
        $loanNumber = (string)($data['loan_number'] ?? '');
        if (!preg_match('/^LN-(\d{6,})$/', $loanNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid loan application.']);
        }
        $decision = (string)($data['decision'] ?? '');
        if (!in_array($decision, ['Approved', 'Rejected'], true)) {
            respond(422, ['error' => 'Choose Approved or Rejected.']);
        }
        $approvedAmount = trim((string)($data['approved_amount'] ?? ''));
        $totalDue = trim((string)($data['total_due'] ?? ''));
        $dueDate = (string)($data['due_date'] ?? '');
        if ($decision === 'Approved') {
            if (!preg_match('/^\d{1,10}(?:\.\d{1,2})?$/', $approvedAmount) || (float)$approvedAmount <= 0) {
                respond(422, ['error' => 'Enter an approved amount greater than zero.']);
            }
            if (!preg_match('/^\d{1,10}(?:\.\d{1,2})?$/', $totalDue) || (float)$totalDue < (float)$approvedAmount) {
                respond(422, ['error' => 'Total due must be at least the approved principal.']);
            }
            $date = DateTime::createFromFormat('!Y-m-d', $dueDate);
            if (!$date || $date->format('Y-m-d') !== $dueDate) {
                respond(422, ['error' => 'Choose a valid due date.']);
            }
        }
        $update = $db->prepare(
            'UPDATE loans SET status = :status, approved_amount = :amount, total_due = :total_due,
                due_date = :due_date, approved_by = :approved_by, approved_at = NOW()
             WHERE id = :id AND status = \'Pending\''
        );
        $update->execute([
            'status' => $decision,
            'amount' => $decision === 'Approved' ? $approvedAmount : null,
            'total_due' => $decision === 'Approved' ? $totalDue : null,
            'due_date' => $decision === 'Approved' ? $dueDate : null,
            'approved_by' => $member['id'],
            'id' => (int)$matches[1],
        ]);
        if (!$update->rowCount()) {
            respond(409, ['error' => 'This application is no longer pending. Refresh the loan list.']);
        }
        respond(200, ['message' => 'Loan application ' . strtolower($decision) . '.']);
    }

    if ($action === 'disburse-loan' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || !in_array($member['role'], ['Admin', 'Treasurer'], true)) {
            respond(403, ['error' => 'Only a treasurer or administrator can disburse a loan.']);
        }
        $loanNumber = (string)($data['loan_number'] ?? '');
        if (!preg_match('/^LN-(\d{6,})$/', $loanNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid approved loan.']);
        }
        $update = $db->prepare(
            'UPDATE loans SET status = \'Active\', disbursed_by = :disbursed_by, disbursed_at = NOW()
             WHERE id = :id AND status = \'Approved\''
        );
        $update->execute(['disbursed_by' => $member['id'], 'id' => (int)$matches[1]]);
        if (!$update->rowCount()) {
            respond(409, ['error' => 'Only an approved, undistributed loan can be disbursed.']);
        }
        respond(200, ['message' => 'Loan disbursed and activated.']);
    }

    if ($action === 'loan-repayments' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view repayments.']);
        }
        $loanNumber = (string)($_GET['loan_number'] ?? '');
        if (!preg_match('/^LN-(\d{6,})$/', $loanNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid loan.']);
        }
        $canViewAll = in_array($member['role'], ['Admin', 'Treasurer', 'Chairperson'], true);
        $query = $db->prepare(
            'SELECT lr.id, lr.amount, lr.payment_method, lr.reference, lr.status, lr.paid_at,
                    lr.member_id, m.full_name, m.member_number
             FROM loan_repayments lr JOIN members m ON m.id = lr.member_id
             WHERE lr.loan_id = :loan_id ORDER BY lr.created_at DESC, lr.id DESC'
        );
        $query->execute(['loan_id' => (int)$matches[1]]);
        $loan = $db->prepare('SELECT member_id FROM loans WHERE id = :loan_id');
        $loan->execute(['loan_id' => (int)$matches[1]]);
        $loanMember = $loan->fetch();
        if (!$loanMember || (!$canViewAll && (int)$loanMember['member_id'] !== (int)$member['id'])) {
            respond(404, ['error' => 'Loan not found.']);
        }
        $records = array_map(static function (array $record): array {
            $record['receipt_number'] = 'LR-' . str_pad((string)$record['id'], 6, '0', STR_PAD_LEFT);
            unset($record['id'], $record['member_id']);
            return $record;
        }, $query->fetchAll());
        respond(200, ['repayments' => $records]);
    }

    if ($action === 'loan-repayment' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to record a repayment.']);
        }
        $loanNumber = (string)($data['loan_number'] ?? '');
        if (!preg_match('/^LN-(\d{6,})$/', $loanNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid active loan.']);
        }
        $canRecordForOthers = in_array($member['role'], ['Admin', 'Treasurer'], true);
        $amount = trim((string)($data['amount'] ?? ''));
        $methodValue = (string)($data['payment_method'] ?? '');
        $reference = trim((string)($data['reference'] ?? ''));
        $paidAt = (string)($data['paid_at'] ?? '');
        if (!preg_match('/^\d{1,10}(?:\.\d{1,2})?$/', $amount) || (float)$amount <= 0) {
            respond(422, ['error' => 'Enter a repayment greater than zero.']);
        }
        if (!in_array($methodValue, ['Cash', 'Bank', 'Mobile money'], true)) {
            respond(422, ['error' => 'Choose a valid payment method.']);
        }
        if ($methodValue === 'Mobile money' && $reference === '') {
            respond(422, ['error' => 'Enter the M-Pesa or mobile money reference.']);
        }
        if (strlen($reference) > 100 || ($methodValue === 'Mobile money' && strlen($reference) > 50)) {
            respond(422, ['error' => 'The payment reference is too long.']);
        }
        $date = DateTime::createFromFormat('!Y-m-d', $paidAt);
        if (!$date || $date->format('Y-m-d') !== $paidAt) {
            respond(422, ['error' => 'Choose a valid payment date.']);
        }
        $db->beginTransaction();
        $loanQuery = $db->prepare('SELECT * FROM loans WHERE id = :id FOR UPDATE');
        $loanQuery->execute(['id' => (int)$matches[1]]);
        $loan = $loanQuery->fetch();
        if (!$loan || $loan['status'] !== 'Active' || (!$canRecordForOthers && (int)$loan['member_id'] !== (int)$member['id'])) {
            $db->rollBack();
            respond(404, ['error' => 'Active loan not found for this member.']);
        }
        $totals = $db->prepare(
            'SELECT COALESCE(SUM(amount), 0) FROM loan_repayments WHERE loan_id = :loan_id'
        );
        $totals->execute(['loan_id' => $loan['id']]);
        $remaining = (float)$loan['total_due'] - (float)$totals->fetchColumn();
        if ((float)$amount > $remaining) {
            $db->rollBack();
            respond(422, ['error' => 'Repayment exceeds the remaining loan balance.']);
        }
        $insert = $db->prepare(
            'INSERT INTO loan_repayments (loan_id, member_id, recorded_by, amount, payment_method, reference, status, paid_at)
             VALUES (:loan_id, :member_id, :recorded_by, :amount, :method, :reference, \'Pending\', :paid_at)'
        );
        $insert->execute([
            'loan_id' => $loan['id'],
            'member_id' => $loan['member_id'],
            'recorded_by' => $member['id'],
            'amount' => $amount,
            'method' => $methodValue,
            'reference' => $reference !== '' ? $reference : null,
            'paid_at' => $paidAt,
        ]);
        $repaymentNumber = 'LR-' . str_pad((string)$db->lastInsertId(), 6, '0', STR_PAD_LEFT);
        $db->commit();
        respond(201, ['message' => 'Repayment recorded and is pending verification.', 'receipt_number' => $repaymentNumber]);
    }

    if ($action === 'verify-loan-repayment' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || !in_array($member['role'], ['Admin', 'Treasurer'], true)) {
            respond(403, ['error' => 'Only a treasurer or administrator can verify repayments.']);
        }
        $repaymentNumber = (string)($data['receipt_number'] ?? '');
        if (!preg_match('/^LR-(\d{6,})$/', $repaymentNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid repayment receipt.']);
        }
        $db->beginTransaction();
        $query = $db->prepare(
            'SELECT lr.id, lr.loan_id, lr.amount, lr.status, l.total_due
             FROM loan_repayments lr JOIN loans l ON l.id = lr.loan_id
             WHERE lr.id = :id FOR UPDATE'
        );
        $query->execute(['id' => (int)$matches[1]]);
        $repayment = $query->fetch();
        if (!$repayment || $repayment['status'] !== 'Pending') {
            $db->rollBack();
            respond(404, ['error' => 'Pending repayment not found.']);
        }
        $totals = $db->prepare("SELECT COALESCE(SUM(amount), 0) FROM loan_repayments WHERE loan_id = :loan_id AND status = 'Verified'");
        $totals->execute(['loan_id' => $repayment['loan_id']]);
        if ((float)$totals->fetchColumn() + (float)$repayment['amount'] > (float)$repayment['total_due']) {
            $db->rollBack();
            respond(409, ['error' => 'Verifying this repayment would exceed the loan balance.']);
        }
        $updateRepayment = $db->prepare("UPDATE loan_repayments SET status = 'Verified' WHERE id = :id AND status = 'Pending'");
        $updateRepayment->execute(['id' => $repayment['id']]);
        $sum = $db->prepare("SELECT COALESCE(SUM(amount), 0) FROM loan_repayments WHERE loan_id = :loan_id AND status = 'Verified'");
        $sum->execute(['loan_id' => $repayment['loan_id']]);
        if ((float)$sum->fetchColumn() >= (float)$repayment['total_due']) {
            $markPaid = $db->prepare("UPDATE loans SET status = 'Paid' WHERE id = :loan_id AND status = 'Active'");
            $markPaid->execute(['loan_id' => $repayment['loan_id']]);
        }
        $db->commit();
        respond(200, ['message' => 'Repayment verified.']);
    }

    if ($action === 'meetings' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view meetings.']);
        }
        $query = $db->query(
            'SELECT mt.id, mt.title, mt.description, mt.location, mt.starts_at, mt.status, mt.created_at,
                    m.full_name AS organizer_name
             FROM meetings mt JOIN members m ON m.id = mt.created_by
             ORDER BY mt.starts_at DESC, mt.id DESC'
        );
        $records = array_map(static function (array $record): array {
            $record['meeting_number'] = 'MTG-' . str_pad((string)$record['id'], 6, '0', STR_PAD_LEFT);
            unset($record['id']);
            return $record;
        }, $query->fetchAll());
        respond(200, ['meetings' => $records]);
    }

    if ($action === 'meeting' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to schedule a meeting.']);
        }
        if (!in_array($member['role'], ['Admin', 'Secretary', 'Chairperson'], true)) {
            respond(403, ['error' => 'Only an administrator, secretary, or chairperson can schedule meetings.']);
        }
        $title = trim((string)($data['title'] ?? ''));
        $description = trim((string)($data['description'] ?? ''));
        $location = trim((string)($data['location'] ?? ''));
        $startsAtInput = (string)($data['starts_at'] ?? '');
        $startsAt = DateTime::createFromFormat('!Y-m-d\TH:i', $startsAtInput);
        $dateErrors = DateTime::getLastErrors();
        if ($title === '' || mb_strlen($title) > 160) {
            respond(422, ['error' => 'Meeting title is required and must be 160 characters or fewer.']);
        }
        if ($location === '' || mb_strlen($location) > 200) {
            respond(422, ['error' => 'Meeting location is required and must be 200 characters or fewer.']);
        }
        if (mb_strlen($description) > 2000) {
            respond(422, ['error' => 'Meeting description must be 2000 characters or fewer.']);
        }
        if (!$startsAt || ($dateErrors !== false && ($dateErrors['warning_count'] > 0 || $dateErrors['error_count'] > 0)) || $startsAt->format('Y-m-d\TH:i') !== $startsAtInput) {
            respond(422, ['error' => 'Choose a valid meeting date and time.']);
        }
        $insert = $db->prepare(
            'INSERT INTO meetings (title, description, location, starts_at, created_by)
             VALUES (:title, :description, :location, :starts_at, :created_by)'
        );
        $insert->execute([
            'title' => $title,
            'description' => $description !== '' ? $description : null,
            'location' => $location,
            'starts_at' => $startsAt->format('Y-m-d H:i:s'),
            'created_by' => $member['id'],
        ]);
        respond(201, [
            'message' => 'Meeting scheduled.',
            'meeting_number' => 'MTG-' . str_pad((string)$db->lastInsertId(), 6, '0', STR_PAD_LEFT),
        ]);
    }

    if ($action === 'meeting-status' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to update a meeting.']);
        }
        if (!in_array($member['role'], ['Admin', 'Secretary', 'Chairperson'], true)) {
            respond(403, ['error' => 'Only an administrator, secretary, or chairperson can update meeting status.']);
        }
        $meetingNumber = (string)($data['meeting_number'] ?? '');
        if (!preg_match('/^MTG-(\d{6,})$/', $meetingNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid meeting.']);
        }
        $status = (string)($data['status'] ?? '');
        if (!in_array($status, ['Completed', 'Cancelled'], true)) {
            respond(422, ['error' => 'Choose Completed or Cancelled.']);
        }
        $update = $db->prepare(
            'UPDATE meetings SET status = :status, status_updated_by = :member_id
             WHERE id = :id AND status = \'Scheduled\''
        );
        $update->execute(['status' => $status, 'member_id' => $member['id'], 'id' => (int)$matches[1]]);
        if (!$update->rowCount()) {
            respond(409, ['error' => 'Meeting not found or no longer scheduled. Refresh and try again.']);
        }
        respond(200, ['message' => 'Meeting marked ' . strtolower($status) . '.']);
    }

    if ($action === 'minutes' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view meeting minutes.']);
        }
        $canViewDrafts = in_array($member['role'], ['Admin', 'Secretary'], true);
        $visibility = $canViewDrafts ? '' : " AND mm.status = 'Published'";
        $query = $db->query(
            'SELECT mm.id, mm.title, mm.content, mm.status, mm.updated_at,
                    mt.id AS meeting_id, mt.title AS meeting_title, mt.starts_at, mt.location,
                    author.full_name AS author_name
             FROM meeting_minutes mm
             JOIN meetings mt ON mt.id = mm.meeting_id
             JOIN members author ON author.id = mm.updated_by
             WHERE mt.status <> \'Cancelled\'' . $visibility . ' ORDER BY mt.starts_at DESC, mm.id DESC'
        );
        $records = array_map(static function (array $record): array {
            $record['minutes_number'] = 'MIN-' . str_pad((string)$record['id'], 6, '0', STR_PAD_LEFT);
            $record['meeting_number'] = 'MTG-' . str_pad((string)$record['meeting_id'], 6, '0', STR_PAD_LEFT);
            unset($record['id'], $record['meeting_id']);
            return $record;
        }, $query->fetchAll());
        respond(200, ['minutes' => $records, 'can_edit' => $canViewDrafts]);
    }

    if ($action === 'minutes' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to save meeting minutes.']);
        }
        if (!in_array($member['role'], ['Admin', 'Secretary'], true)) {
            respond(403, ['error' => 'Only an administrator or secretary can create meeting minutes.']);
        }
        $meetingNumber = (string)($data['meeting_number'] ?? '');
        $title = trim((string)($data['title'] ?? ''));
        $content = trim((string)($data['content'] ?? ''));
        $status = (string)($data['status'] ?? 'Draft');
        if (!preg_match('/^MTG-(\d{6,})$/', $meetingNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid meeting.']);
        }
        if ($title === '' || mb_strlen($title) > 160 || $content === '' || mb_strlen($content) > 2000000) {
            respond(422, ['error' => 'Enter a title and minutes text within the allowed limits.']);
        }
        if (!in_array($status, ['Draft', 'Published'], true)) {
            respond(422, ['error' => 'Choose Draft or Published.']);
        }
        $meeting = $db->prepare("SELECT id FROM meetings WHERE id = :id AND status <> 'Cancelled'");
        $meeting->execute(['id' => (int)$matches[1]]);
        $target = $meeting->fetch();
        if (!$target) {
            respond(404, ['error' => 'Meeting not found or cancelled.']);
        }
        try {
            $insert = $db->prepare(
                'INSERT INTO meeting_minutes (meeting_id, title, content, status, created_by, updated_by)
                 VALUES (:meeting_id, :title, :content, :status, :created_by, :updated_by)'
            );
            $insert->execute([
                'meeting_id' => $target['id'],
                'title' => $title,
                'content' => $content,
                'status' => $status,
                'created_by' => $member['id'],
                'updated_by' => $member['id'],
            ]);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') {
                respond(409, ['error' => 'Minutes already exist for this meeting. Open the existing document to edit it.']);
            }
            throw $error;
        }
        respond(201, ['message' => $status === 'Published' ? 'Minutes published.' : 'Draft saved.', 'minutes_number' => 'MIN-' . str_pad((string)$db->lastInsertId(), 6, '0', STR_PAD_LEFT)]);
    }

    if ($action === 'minutes-update' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || !in_array($member['role'], ['Admin', 'Secretary'], true)) {
            respond(403, ['error' => 'Only an administrator or secretary can edit meeting minutes.']);
        }
        $minutesNumber = (string)($data['minutes_number'] ?? '');
        if (!preg_match('/^MIN-(\d{6,})$/', $minutesNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid minutes document.']);
        }
        $title = trim((string)($data['title'] ?? ''));
        $content = trim((string)($data['content'] ?? ''));
        $status = (string)($data['status'] ?? 'Draft');
        if ($title === '' || mb_strlen($title) > 160 || $content === '' || mb_strlen($content) > 2000000) {
            respond(422, ['error' => 'Enter a title and minutes text within the allowed limits.']);
        }
        if (!in_array($status, ['Draft', 'Published'], true)) {
            respond(422, ['error' => 'Choose Draft or Published.']);
        }
        $update = $db->prepare(
            'UPDATE meeting_minutes SET title = :title, content = :content, status = :status, updated_by = :updated_by
             WHERE id = :id'
        );
        $update->execute(['title' => $title, 'content' => $content, 'status' => $status, 'updated_by' => $member['id'], 'id' => (int)$matches[1]]);
        if (!$update->rowCount()) {
            $exists = $db->prepare('SELECT id FROM meeting_minutes WHERE id = :id');
            $exists->execute(['id' => (int)$matches[1]]);
            if (!$exists->fetch()) {
                respond(404, ['error' => 'Minutes document not found.']);
            }
        }
        respond(200, ['message' => $status === 'Published' ? 'Minutes published.' : 'Draft saved.']);
    }

    if ($action === 'expenses' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view expenses.']);
        }
        if (!in_array($member['role'], ['Admin', 'Treasurer'], true)) {
            respond(403, ['error' => 'Only a treasurer or administrator can view the expense ledger.']);
        }
        $query = $db->query(
            'SELECT e.id, e.payee, e.category, e.description, e.amount, e.reference, e.expense_date,
                    e.status, e.created_at, recorder.full_name AS recorded_by_name,
                    verifier.full_name AS verified_by_name
             FROM expenses e
             JOIN members recorder ON recorder.id = e.recorded_by
             LEFT JOIN members verifier ON verifier.id = e.verified_by
             ORDER BY e.expense_date DESC, e.id DESC'
        );
        $records = array_map(static function (array $record): array {
            $record['expense_number'] = 'EXP-' . str_pad((string)$record['id'], 6, '0', STR_PAD_LEFT);
            unset($record['id']);
            return $record;
        }, $query->fetchAll());
        $summary = $db->query(
            'SELECT COALESCE(SUM(CASE WHEN status = \'Verified\' THEN amount ELSE 0 END), 0) AS total_verified,
                    COALESCE(SUM(CASE WHEN status = \'Pending\' THEN amount ELSE 0 END), 0) AS total_pending,
                    COALESCE(SUM(CASE WHEN status = \'Verified\' AND YEAR(expense_date) = YEAR(CURDATE()) AND MONTH(expense_date) = MONTH(CURDATE()) THEN amount ELSE 0 END), 0) AS current_month_verified,
                    COALESCE(SUM(CASE WHEN status = \'Pending\' AND YEAR(expense_date) = YEAR(CURDATE()) AND MONTH(expense_date) = MONTH(CURDATE()) THEN amount ELSE 0 END), 0) AS current_month_pending
             FROM expenses'
        )->fetch();
        respond(200, ['expenses' => $records, 'summary' => $summary]);
    }

    if ($action === 'expense' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to record an expense.']);
        }
        if (!in_array($member['role'], ['Admin', 'Treasurer'], true)) {
            respond(403, ['error' => 'Only a treasurer or administrator can record expenses.']);
        }
        $payee = trim((string)($data['payee'] ?? ''));
        $category = trim((string)($data['category'] ?? ''));
        $description = trim((string)($data['description'] ?? ''));
        $amount = trim((string)($data['amount'] ?? ''));
        $reference = trim((string)($data['reference'] ?? ''));
        $expenseDate = (string)($data['expense_date'] ?? '');
        if ($payee === '' || mb_strlen($payee) > 160) {
            respond(422, ['error' => 'Enter a payee name up to 160 characters.']);
        }
        if ($category === '' || mb_strlen($category) > 100) {
            respond(422, ['error' => 'Enter an expense category up to 100 characters.']);
        }
        if (mb_strlen($description) > 500 || strlen($reference) > 100) {
            respond(422, ['error' => 'The description or reference is too long.']);
        }
        if (!preg_match('/^\d{1,10}(?:\.\d{1,2})?$/', $amount) || (float)$amount <= 0) {
            respond(422, ['error' => 'Enter an expense amount greater than zero.']);
        }
        $date = DateTime::createFromFormat('!Y-m-d', $expenseDate);
        if (!$date || $date->format('Y-m-d') !== $expenseDate) {
            respond(422, ['error' => 'Choose a valid expense date.']);
        }
        $insert = $db->prepare(
            'INSERT INTO expenses (payee, category, description, amount, reference, expense_date, recorded_by)
             VALUES (:payee, :category, :description, :amount, :reference, :expense_date, :recorded_by)'
        );
        $insert->execute([
            'payee' => $payee,
            'category' => $category,
            'description' => $description !== '' ? $description : null,
            'amount' => $amount,
            'reference' => $reference !== '' ? $reference : null,
            'expense_date' => $expenseDate,
            'recorded_by' => $member['id'],
        ]);
        respond(201, [
            'message' => 'Expense recorded and is pending verification.',
            'expense_number' => 'EXP-' . str_pad((string)$db->lastInsertId(), 6, '0', STR_PAD_LEFT),
            'status' => 'Pending',
        ]);
    }

    if ($action === 'verify-expense' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || !in_array($member['role'], ['Admin', 'Treasurer'], true)) {
            respond(403, ['error' => 'Only a treasurer or administrator can verify expenses.']);
        }
        $expenseNumber = (string)($data['expense_number'] ?? '');
        if (!preg_match('/^EXP-(\d{6,})$/', $expenseNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid expense record.']);
        }
        $update = $db->prepare("UPDATE expenses SET status = 'Verified', verified_by = :member_id, verified_at = NOW() WHERE id = :id AND status = 'Pending'");
        $update->execute(['member_id' => $member['id'], 'id' => (int)$matches[1]]);
        if (!$update->rowCount()) {
            respond(404, ['error' => 'Pending expense not found.']);
        }
        respond(200, ['message' => 'Expense verified.']);
    }

    if ($action === 'attendance' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view attendance.']);
        }
        $canManage = in_array($member['role'], ['Admin', 'Secretary', 'Chairperson'], true);
        $meetingNumber = (string)($_GET['meeting_number'] ?? '');
        if ($meetingNumber === '' && !$canManage) {
            $history = $db->prepare(
                'SELECT mt.title, mt.starts_at, mt.location, mt.status AS meeting_status,
                        a.attendance_status
                 FROM attendance_records a
                 JOIN meetings mt ON mt.id = a.meeting_id
                 WHERE a.member_id = :member_id
                 ORDER BY mt.starts_at DESC, mt.id DESC'
            );
            $history->execute(['member_id' => $member['id']]);
            respond(200, ['attendance' => $history->fetchAll(), 'can_manage' => false]);
        }
        if (!preg_match('/^MTG-(\d{6,})$/', $meetingNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid meeting.']);
        }
        $meetingQuery = $db->prepare('SELECT id, title, starts_at, location, status FROM meetings WHERE id = :id');
        $meetingQuery->execute(['id' => (int)$matches[1]]);
        $meeting = $meetingQuery->fetch();
        if (!$meeting) {
            respond(404, ['error' => 'Meeting not found.']);
        }
        if ($canManage) {
            $query = $db->prepare(
                'SELECT m.member_number, m.full_name, a.attendance_status
                 FROM members m
                 LEFT JOIN attendance_records a ON a.member_id = m.id AND a.meeting_id = :meeting_id
                 WHERE m.status = \'Active\' ORDER BY m.full_name'
            );
            $query->execute(['meeting_id' => $meeting['id']]);
        } else {
            $query = $db->prepare(
                'SELECT m.member_number, m.full_name, a.attendance_status
                 FROM members m
                 LEFT JOIN attendance_records a ON a.member_id = m.id AND a.meeting_id = :meeting_id
                 WHERE m.id = :member_id'
            );
            $query->execute(['meeting_id' => $meeting['id'], 'member_id' => $member['id']]);
        }
        unset($meeting['id']);
        $meeting['meeting_number'] = 'MTG-' . str_pad((string)$matches[1], 6, '0', STR_PAD_LEFT);
        respond(200, ['meeting' => $meeting, 'attendance' => $query->fetchAll(), 'can_manage' => $canManage]);
    }

    if ($action === 'attendance' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to save attendance.']);
        }
        if (!in_array($member['role'], ['Admin', 'Secretary', 'Chairperson'], true)) {
            respond(403, ['error' => 'Only an administrator, secretary, or chairperson can edit attendance.']);
        }
        $meetingNumber = (string)($data['meeting_number'] ?? '');
        if (!preg_match('/^MTG-(\d{6,})$/', $meetingNumber, $matches)) {
            respond(422, ['error' => 'Choose a valid meeting.']);
        }
        $records = $data['attendance'] ?? null;
        if (!is_array($records) || count($records) < 1 || count($records) > 1000) {
            respond(422, ['error' => 'Choose an attendance status for each active member.']);
        }
        $meetingQuery = $db->prepare("SELECT id FROM meetings WHERE id = :id AND status <> 'Cancelled'");
        $meetingQuery->execute(['id' => (int)$matches[1]]);
        $meeting = $meetingQuery->fetch();
        if (!$meeting) {
            respond(404, ['error' => 'Meeting not found or cancelled.']);
        }
        $findMember = $db->prepare('SELECT id FROM members WHERE member_number = :number AND status = \'Active\'');
        $save = $db->prepare(
            'INSERT INTO attendance_records (meeting_id, member_id, attendance_status, recorded_by)
             VALUES (:meeting_id, :member_id, :status, :recorded_by)
             ON DUPLICATE KEY UPDATE attendance_status = VALUES(attendance_status), recorded_by = VALUES(recorded_by)'
        );
        $db->beginTransaction();
        foreach ($records as $record) {
            if (!is_array($record) || !in_array($record['status'] ?? '', ['Present', 'Absent', 'Apology'], true)) {
                $db->rollBack();
                respond(422, ['error' => 'Each member must have a valid attendance status.']);
            }
            $findMember->execute(['number' => (string)($record['member_number'] ?? '')]);
            $target = $findMember->fetch();
            if (!$target) {
                $db->rollBack();
                respond(422, ['error' => 'An attendance member is not active. Refresh and try again.']);
            }
            $save->execute([
                'meeting_id' => $meeting['id'],
                'member_id' => $target['id'],
                'status' => $record['status'],
                'recorded_by' => $member['id'],
            ]);
        }
        $db->commit();
        respond(200, ['message' => 'Attendance register saved.', 'saved' => count($records)]);
    }

    if ($action === 'members' && $method === 'GET') {
        $member = current_member($db);
        if (!$member) {
            respond(401, ['error' => 'Sign in to view members.']);
        }
        if (in_array($member['role'], ['Admin', 'Secretary', 'Treasurer', 'Chairperson'], true)) {
            $query = $db->query('SELECT * FROM members ORDER BY full_name');
            respond(200, ['members' => array_map('public_member', $query->fetchAll())]);
        }
        respond(200, ['members' => [public_member($member)]]);
    }

    if ($action === 'update-member' && $method === 'POST') {
        $data = request_data();
        require_csrf($data);
        $member = current_member($db);
        if (!$member || $member['role'] !== 'Admin') {
            respond(403, ['error' => 'Only an administrator can change member roles or status.']);
        }
        $roles = ['Member', 'Treasurer', 'Secretary', 'Chairperson', 'Admin'];
        $statuses = ['Active', 'Inactive'];
        $memberNumber = trim((string)($data['member_number'] ?? ''));
        $role = (string)($data['role'] ?? '');
        $status = (string)($data['status'] ?? '');
        if (!in_array($role, $roles, true) || !in_array($status, $statuses, true)) {
            respond(422, ['error' => 'Choose a valid role and account status.']);
        }

        $db->beginTransaction();
        $query = $db->prepare('SELECT * FROM members WHERE member_number = :number FOR UPDATE');
        $query->execute(['number' => $memberNumber]);
        $target = $query->fetch();
        if (!$target) {
            $db->rollBack();
            respond(404, ['error' => 'Member not found.']);
        }
        if ($target['role'] === 'Admin' && $target['status'] === 'Active' && ($role !== 'Admin' || $status !== 'Active')) {
            $admins = $db->query("SELECT COUNT(*) FROM members WHERE role = 'Admin' AND status = 'Active'")->fetchColumn();
            if ((int)$admins <= 1) {
                $db->rollBack();
                respond(409, ['error' => 'Keep at least one active administrator.']);
            }
        }
        $update = $db->prepare('UPDATE members SET role = :role, status = :status WHERE id = :id');
        $update->execute(['role' => $role, 'status' => $status, 'id' => $target['id']]);
        $db->commit();
        respond(200, ['message' => 'Member updated.']);
    }

    respond(404, ['error' => 'Endpoint not found.']);
} catch (PDOException $error) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    if ($error->getCode() === '23000') {
        respond(409, ['error' => 'That email address or phone number is already registered.']);
    }
    error_log($error->getMessage());
    respond(503, ['error' => 'Database unavailable. Import database.sql and check the database settings.']);
} catch (Throwable $error) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    error_log($error->getMessage());
    respond(500, ['error' => 'The request could not be completed.']);
}