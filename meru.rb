require 'grape'
require 'mysql2'
require 'mail'
require 'json'


module Meru
  class API < Grape::API
    version 'v1', using: :header, vendor: 'meru'
    format :json
    conf = JSON.parse(File.read("config.json"))
    dbconf = conf["database"]

    client = Mysql2::Client.new(:host => dbconf["host"],
                                :username => dbconf["username"],
                                :password => dbconf["password"],
                                :database => dbconf["database"])

    helpers do
      def valid_name(name)
        # Technically an escaped @ is valid in an
        # email address, but we reject it. Fortunately,
        # this is only used for creation and I'm okay
        # with limiting those crazy addresses from existing
        return false if name =~ /\-|@|^$/ || name.length > 100
        Mail::Address.new(name) rescue false
        true
      end

      def valid_pass(pass)
        pass.length >= 8
      end
    end

    resource :account do
      desc 'Creates an account'
      params do
        requires :user, type: String, desc: 'Username'
        requires :password, type: String, desc: 'Password'
        requires :invite, type: String, desc: 'Invite code'
        requires :domain, type: Integer, desc: 'Domain'
      end
      post do
        uname = client.escape(params[:user]).downcase.strip
        password = client.escape(params[:password])
        invite = client.escape(params[:invite])
        domainid = params[:domain] # no need to escape Int

        error!("Invalid username", 400) unless valid_name(uname)

        existing_user = client.query("SELECT
  1
FROM
  virtual_users vu,
  virtual_aliases va
WHERE
  vu.domain_id=#{domainid} AND
  va.domain_id=#{domainid} AND
  (
    vu.user='#{uname}' OR
    va.source='#{uname}'
  )
LIMIT 1")
        error!("Username taken", 400) if existing_user.first

        error!("Invalid password", 400) unless valid_pass(params[:password])

        # No way to get affected rows or we could do this with one update,
        # not a select and an update. That was the original intent of this
        # table design
        res = client.query("SELECT id FROM virtual_users WHERE invite_code='#{invite}' AND domain_id=#{domainid} LIMIT 1")
        error!('Invalid invite') unless res.first

        client.query("UPDATE
  virtual_users
SET
  user='#{uname}',
  password=ENCRYPT('#{password}', CONCAT(\"$6$\", SUBSTRING(SHA(RAND()), -16))),
  invite_code=NULL
WHERE
  id=#{res.first["id"]}
LIMIT 1")
        {ok: 1} # Kinda take it on faith nothing went horribly wrong :S
      end

      resource :password do
        desc 'Change account password'
        params do
          requires :email, type: String, desc: "Email address"
          requires :oldpassword, type: String, desc: "Current password"
          requires :newpassword, type: String, desc: "New password"
        end
        post do
          email = params[:email].split("@").map{|x| client.escape(x)}
          oldpass = params[:oldpassword] # not used in sql query
          newpass = client.escape(params[:newpassword])
          email.size == 2 || error!("Invalid email", 400)
          validate_pass(params[:newpassword]) || error!("Invalid new pass", 400)
          user = client.query("SELECT
            u.id AS id,
            u.password AS password
          FROM
            virtual_users u,
            virtual_domains d
          WHERE
            u.domain_id = d.id AND
            d.name='#{email[1]}' AND
            u.user='#{email[0]}'
          LIMIT 1").first
          error!("Invalid user") unless user

          magic, salt = user["password"].split('$')[1,2]
          oldpass.crypt("$#{magic}$#{salt}") == user["password"] || error!("Invalid password")

          client.query("UPDATE virtual_users SET
          password=ENCRYPT('#{newpass}', CONCAT(\"$6$\", SUBSTRING(SHA(RAND()), -16)))
          WHERE id=#{user["id"]}")
          {ok: 1}
        end
      end
    end

    resource :domain do
      desc 'Get a domain name'
      params do
        requires :id, type: Integer, desc: "Domain id"
      end
      get do
        dname = client.query("SELECT name FROM virtual_domains WHERE id=#{params[:id]}").first

        dname || {error: "No such domain"}
      end
    end


    resource :invite do
      desc 'Create a new invite'
      params do
        requires :email, type: String, desc: 'Your email'
      end
      post do
        email = params[:email].split("@").map{|x| client.escape(x)}

        # Verify this is actually a user of our site
        user = client.query("SELECT
          u.domain_id AS domain_id
        FROM
          virtual_users u,
          virtual_domains d
        WHERE
          u.domain_id = d.id AND
          d.name='#{email[1]}' AND
          u.user='#{email[0]}'
        LIMIT 1").first
        error!("No such email", 400) unless user
        domain_id = user["domain_id"]

        # User exists. Create an invite for this domain and send it to them
        invite_code = Random.new.bytes(35).split('').map{|i| i.ord.to_s(16)}.join[0...35]
        client.query("INSERT INTO virtual_users(domain_id, invite_code) VALUES(#{domain_id}, '#{invite_code}'")

        # Now email the invite to the user so they can pass it on to whoever
        mail = Mail.new do
          from conf["signup_from"]
          to params[:email]
          subject conf["subject"]
        end
        mail[:body] = <<EOM
Someone has requested an invite code with your address.
If this was not you, please go here: #{conf["signup_delete_url"] + "?invite=" + invite_code + "&domain=" + domain_id} to remove it.

If it was you, please provide the link below to the person who wants to signup.
Please recall that this works on a system of trust. Only invite a person whom you
feel sure will not abuse the service. Spam will not be tolerated.
#{conf["signup_url"] + '?invite='+invite_code+'&domain='+domain_id}

Best,
#{conf["signup_signame"]}
EOM
        mail.delivery_method :sendmail
        mail.delever!
      end
    end
  end
end

