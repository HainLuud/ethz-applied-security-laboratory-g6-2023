LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
UPDATE `users` SET `pwd` = '$2b$12$f/xOpNjSOS2mNNg7ZeR7FulkOSIsidSU.kKWYgrC8BmkzfyKBgRYO' WHERE `uid` = 'ps';
UPDATE `users` SET `pwd` = '$2b$12$5ibLHy.0C4hsMI2OityQCubteg.WIO0MOC4gzUKCsz5LDCnu4z/tK' WHERE `uid` = 'lb';
UPDATE `users` SET `pwd` = '$2b$12$ErG/RR8F50n3ZydvFvJ7POd/VCit8pscMaVYIGzBE0JWgNl89EUme' WHERE `uid` = 'ms';
UPDATE `users` SET `pwd` = '$2b$12$BD0G5SvJQK1L/Q6AgTYwmuIlHy/QkK6h9eyHbO4FyQQpci7We3jMS' WHERE `uid` = 'a3';
INSERT INTO `users` VALUES ('admin','','','admin@imovies.ch','');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
