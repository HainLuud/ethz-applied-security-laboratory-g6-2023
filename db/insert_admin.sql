LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('admin','','','admin@imovies.ch','');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
