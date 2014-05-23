require 'rubygems'
require 'json'
require 'sequel'


conf = JSON.parse(File.read("config.json"))
dbconf = conf["database"]


DB = Sequel.connect(adapter: :mysql2, host: dbconf["host"],
                    database: dbconf["database"],
                    user: dbconf["username"],
                    password: dbconf["password"])


if ARGV[0] == '--force'
  DB.drop_table :virtual_domains
  DB.drop_table :virtual_users
  DB.drop_table :virtual_aliases
  DB.drop_table :invites
  DB.drop_table :login_sessions
end


DB.create_table :virtual_domains do
  primary_key :id
  String :name, {unique: true, null: false, size: 100}
end

DB.create_table :virtual_users do
  primary_key :id
  String :user, {unique: false, null: false, size: 100}
  String :password, {size: 106, null: false}

  Integer :domain_id, {null: false}

  FalseClass :is_admin, {default: false}

  unique([:user, :domain_id])
end

DB.create_table :invites do
  primary_key :id
  String :code
  Integer :status, {null: true, default: nil}
  Integer :from, {null: false, references: :virtual_users}
  Integer :to, {null: true, default: nil, references: :virtual_users}
  Integer :domain_id, {null: false, references: :virtual_domains}
end


DB.create_table :virtual_aliases do
  primary_key :id
  Integer :domain_id, {null: false, references: :virtual_domains}
  String :source, {null: false, size: 100}
  String :destination, {null: false, size: 200}
  unique([:domain_id, :source])
end

DB.create_table :login_sessions do
  primary_key :id
  Integer :virtual_user_id, {null: false, references: :virtual_users}
  String :session, {null: false, size: 50}
  Timestamp :created_at, {null: false, default: Sequel::SQL::Function.new(:now)}
  String :ip, {null: false, size: 128} # We ready for ipv6 :D
  unique(:virtual_user_id)
end
