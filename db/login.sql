SELECT ul.email, password, firstname, lastname, login_id
FROM user_login ul
JOIN users u
ON ul.email = u.email
WHERE u.email = ${email};