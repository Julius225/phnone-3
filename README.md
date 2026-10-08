# Umoya Circle

Vite builds the frontend; PHP sessions and PDO/MySQL provide authentication and contribution data. The frontend uses the existing DM Sans and Manrope families bundled in `dist`, so production pages do not fetch fonts from an external service.

## Build and distribute

1. Start Apache and MySQL in XAMPP.
2. Import `database.sql` into MySQL. It uses `CREATE TABLE IF NOT EXISTS`, so re-import it on an existing installation to add the loan tables without dropping current member or contribution records.
3. Run `npm install` and `npm run build` from this project folder.
4. Distribute the complete project folder, including `api.php`, `database.sql`, and the generated `dist` directory. Do not distribute `dist` alone: its `api.php` wrapper calls the PHP API in the parent project folder.
5. On the destination computer, place the folder under Apache's document root, configure PHP database environment variables if needed, and open `<project-folder>/dist/`.

Vite's production build uses relative asset URLs. `dist/.htaccess` routes clean paths such as `dist/members` and `dist/contributions` back to the app entry point. Apache must have `mod_rewrite` enabled and allow `.htaccess` overrides. The app detects its deployment subfolder for routes and API calls, so renaming the project folder does not change its asset/API paths.

For local development, start XAMPP, then run `npm run dev`. Set `VITE_PHP_PROXY_TARGET` when the PHP API is not reachable at the configured local XAMPP project path.

## Roles and routes

The client identifies the current page from the URL and filters the existing sidebar entries by the logged-in role. The PHP API independently enforces contribution and member read/write permissions; hiding a link is not treated as authorization.

Members are limited to their own contribution and loan records. Treasurer/Admin can view the full contribution ledger, record for members, disburse loans, and verify repayments. Chairperson can view the member directory, group contribution totals, and loan applications. Admin/Chairperson decide loan applications; the approver explicitly enters the approved amount, total due, and due date. Repayment amounts stay pending until verified. Member Profile, Reports, Treasury, Notifications, and Loans/Repayments use the authenticated session and database APIs.

Meetings are stored in MySQL and can be scheduled or marked completed/cancelled by Admin, Secretary, or Chairperson. Attendance is stored per meeting/member; Members see only their own history, while Admin, Secretary, and Chairperson can edit registers. Meeting minutes are linked one-to-one with a scheduled meeting: Admin/Secretary can save drafts or publish/edit them, and other roles see published documents only. Expenses, group activities, and system settings do not have backend tables/APIs yet; their routes identify them as unavailable rather than displaying sample data.

## Initial administrator

New accounts start as `Member`. After registering the first account, promote it in phpMyAdmin (replace the address with its registered email):

```sql
UPDATE umoya_circle.members
SET role = 'Admin'
WHERE email = 'admin@example.com';
```

Sign out and back in to load the updated role. Keep at least one active administrator.

The PHP API defaults to XAMPP's common local settings (`127.0.0.1`, database `umoya_circle`, user `root`, empty password). Set `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD` for other local installations. Before public deployment, use a least-privilege database account, HTTPS, rate limiting, and an invitation or approval policy for registration.