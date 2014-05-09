require 'rubygems'
require 'json'
require 'sequel'


conf = JSON.parse(File.read("config.json"))
dbconf = conf["database"]


DB = Sequel.connect(adapter: :mysql, host: dbconf["host"],
                    database: dbconf["database"],
                    user: dbconf["username"],
                    password: dbconf["password"])



DB.create_table :virtual_domains do
  primary_key :id
  String :name, {unique: true, null: false, size: 100}
end

DB.create_table :virtual_users do
  primary_key :id
  String :user, {unique: false, null: false, size: 100}
  Integer :domain_id, {null: false}
  String :password, {size: 106, null: false}
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
