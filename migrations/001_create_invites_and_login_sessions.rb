Sequel.migration do
  change do
    create_table :invites do
      primary_key :id
      String :code
      Integer :status, {null: true, default: nil}
      # Ideally, these two would reference mailbox
      String :from, {null: false}
      String :to, {null: true, default: nil}
      String :domain, {null: false}
      Timestamp :created_at, {null: false, default: Sequel::SQL::Function.new(:now)}
      Timestamp :consumed_at, {default: nil}
    end

    create_table :login_sessions do
      primary_key :id
      String :username, {null: false}
      String :session, {null: false, size: 50}
      Timestamp :created_at, {null: false, default: Sequel::SQL::Function.new(:now)}
      String :ip, {null: false, size: 128} # We ready for ipv6 :D
      unique(:username) # A user can only be logged in once
    end
  end
end
