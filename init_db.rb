require 'rubygems'
require 'json'
require 'sequel'


conf = JSON.parse(File.read("config.json"))
dbconf = conf["database"]


DB = Sequel.connect(adapter: :postgres, host: dbconf["host"],
                    database: dbconf["database"],
                    user: dbconf["username"],
                    password: dbconf["password"])


if ARGV[0] == '--force'
  DB.drop_table :invites
  DB.drop_table :login_sessions
end


DB.create_table :invites do
  primary_key :id
  String :code
  Integer :status, {null: true, default: nil}
  # Ideally, these two would reference mailbox
  String :from, {null: false}
  String :to, {null: true, default: nil}
  String :domain, {null: false}
  DateTime :created_at, {null: false, default: Sequel.function(:now)}
  Timestamp :consumed_at, {default: nil}
end

DB.create_table :login_sessions do
  primary_key :id
  String :username, {null: false}
  String :session, {null: false, size: 50}
  DateTime :created_at, {null: false, default: Sequel.function(:now)}
  String :ip, {null: false, size: 128} # We ready for ipv6 :D
  unique(:username)
end
