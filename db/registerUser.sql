INSERT INTO user_login (email, password)
VALUES (
  ${email},
  ${hash}
);

INSERT INTO users (firstname, lastname, email)
VALUES (
  ${firstname},
  ${lastname},
  ${email}
);

-- adding this code below to send back as part of the response -- 
SELECT ul.email, firstname, lastname, login_id
FROM user_login ul
JOIN users u
ON ul.email = u.email
WHERE u.email = ${email};