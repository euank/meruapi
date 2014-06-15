require 'json'
conf = JSON.parse(File.read("config.json"))
dbconf = conf["database"]

`sequel -m migrations postgres://#{dbconf["username"] + ':' + dbconf["password"] + '@' + dbconf["host"] + '/' + dbconf["database"]}`
