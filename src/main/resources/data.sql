INSERT INTO users (username, password, enabled) VALUES
('admin', 'admin', true),
('user', 'user', true);

INSERT INTO authorities (username, authority) VALUES
('user', 'ROLE_USER'),
('admin', 'ROLE_ADMIN');
