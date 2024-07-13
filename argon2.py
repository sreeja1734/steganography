
ph = PasswordHasher()
hash = ph.hash("correct horse battery staple")
print(hash)
ph.verify(hash, "correct horse battery staple")
