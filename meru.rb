require 'rubygems'

require 'grape'
require 'mail'
require 'json'
require 'sequel'
require 'securerandom'


module Meru
  class API < Grape::API
    version 'v1', using: :header, vendor: 'meru'
    format :json
    conf = JSON.parse(File.read("config.json"))
    dbconf = conf["database"]
    DB = Sequel.connect(adapter: :mysql2, host: dbconf["host"],
                        database: dbconf["database"],
                        user: dbconf["username"],
                        password: dbconf["password"])

    class Invite < Sequel::Model; end
    class VirtualUser < Sequel::Model; end
    class VirtualAlias < Sequel::Model; end
    class VirtualDomain < Sequel::Model; end
    class LoginSession < Sequel::Model; end

    helpers do
      def valid_name(name)
        # Technically an escaped @ is valid in an
        # email address, but we reject it. Fortunately,
        # this is only used for creation and I'm okay
        # with limiting those crazy addresses from existing
        return false if name =~ /\-|@|^$/ || name.length > 100
        # Transform this into a true/false
        !!(Mail::Address.new(name) rescue false)
      end

      def valid_pass(pass)
        # TODO, check against dict
        pass.length >= 8
      end

      def hash_pass(pass)
        pass.crypt('$6$' + SecureRandom.hex(16))
      end

      def check_pass(pass, hash)
        magic, salt = hash.split('$')[1,2]
        pass.crypt("$#{magic}$#{salt}") == hash
      end

      def session_user(session, env)
        s = LoginSession.where(session: session).first
        return nil if s.nil?
        # Sessions expire after 2 hours
        if s.created_at + 2.hours < DateTime.now
          return nil
        end
        if s.ip != env['REMOTE_ADDR']
          return nil
        end
        s.virtual_user_id
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
        uname = params[:user].downcase.strip
        password = params[:password]
        invite = params[:invite]
        domainid = params[:domain]

        error!("Invalid username", 400) unless valid_name(uname)

        # Make sure the username is new
        # Technically this might be a race condition;
        # unfortunately, we can't enforce a uniqueness
        # across both aliases and users as easily as a single
        # unique constraint sql serverside, so this will do for now

        if !(DB.from(:virtual_users, :virtual_aliases).
                    where(virtual_users__domain_id: domainid).
                    where(virtual_aliases__domain_id: domainid).
                    where(Sequel.expr(virtual_users__user: uname) | 
                      Sequel.expr(virtual_aliases__source: uname)).empty?)

          error!("Username taken", 400)
        end

        error!("Invalid password", 400) unless valid_pass(params[:password])

        begin
          DB.transaction do
            invite = Invite.where("code = ? AND domain_id = ? AND status IS NULL",
                                      invite, domainid).first
            raise "Invalid invite" unless invite


            user = VirtualUser.new
            user.domain_id = invite.domain_id
            user.user = uname
            user.password = hash_pass(password)
            user.save

            invite.status = 1 # used
            invite.to = user.id
            invite.save
          end
        rescue Exception => e
          error!(e.to_s, 400)
        end

        {ok: 1}
      end
    end

    resource :login do
      desc 'Login to an account'
      params do
        requires :email, type: String, desc: 'Email address'
        requires :password, type: String, desc: 'Password'
      end
      post do
        name,domain = params[:email].split('@')
        vd = VirtualDomain.where(name: domain).first

        error!("Invalid domain", 400) unless vd

        domainid = vd.id

        vu = VirtualUser.where(user: name, domain_id: domainid).first
        error!("Invalid password", 404) unless vu
        hash = vu.password
        check_pass(params[:password], hash) || error!("Invalid password", 404)

        # Pass is okay, let's make them a session
        # Delete existing sessions
        LoginSession.where(virtual_user_id: vu.id).delete
        session = LoginSession.new
        session.virtual_user_id = vu.id
        session.session = SecureRandom.hex(50)
        session.ip = env['REMOTE_ADDR']
        session.save rescue error!("Couldn't create a login session", 400)
        {ok: 1, session: session.session}
      end

      desc "Check if you're logged in"
      params do; end
      get do
        if session_user(cookies[:session], env).nil?
          {ok: 1, logged_in: false}
        else
          {ok: 1, logged_in: true}
        end
      end

      desc 'Logout'
      params do; end
      delete do
        LoginSession.where(session: cookies[:session]).delete
        {ok: 1}
      end
    end

    resource :password do
      desc 'Change account password'
      params do
        requires :email, type: String, desc: "Email address"
        requires :oldpassword, type: String, desc: "Current password"
        requires :newpassword, type: String, desc: "New password"
      end
      post do
        email = params[:email].split("@").map(&:downcase)
        oldpass = params[:oldpassword]
        newpass = params[:newpassword]
        email.size == 2 || error!("Invalid email", 400)
        valid_pass(params[:newpassword]) || error!("Invalid new pass", 400)

        user = VirtualUser.join(VirtualDomain, id: :domain_id).
          where(name: email[1]).
          where(user: email[0]).first

        user = VirtualUser[user.id] rescue nil

        error!("Invalid user") unless user

        # Check their old password is right
        check_pass(oldpass, user[:password]) || error!("Invalid password")

        # Update em
        user.password = hash_pass(newpass)
        user.save
        {ok: 1}
      end
    end

    resource :domain do
      desc 'Get a domain name'
      params do
        requires :id, type: Integer, desc: "Domain id"
      end
      get do
        domain = VirtualDomain.where(id: params[:id]).first
        error!("No such domain", 400) unless domain
        {ok: 1, name: domain.name} || error!("No such domain", 400)
      end
    end


    resource :initial_setup do
      desc "Get if we need to setup"
      params do
      end
      get do
        error!("Already setup", 400) if VirtualUser.first
      end

      desc "Setup the primary domain and admin user"
      params do
        requires :domain, type: String, desc: 'Primary Domain'
        requires :username, type: String, desc: 'Admin username'
        requires :password, type: String, desc: 'Admin password'
        requires :setup_pass, type: String, desc: 'Setup password'
      end
      post do
        unless params[:setup_pass] == conf['setup_pass']
          error!("Invalid setup password", 403)
        end
        error!("Invalid username", 400) unless valid_name(params[:username])
        error!("Invalid password", 400) unless valid_name(params[:password])
        # Take it on faith the domain is okay for now

        # Create domain
        vd = VirtualDomain.new
        vd.name = params[:domain]
        vd.save rescue error!("Error creating domain", 400)

        # Admin user
        vu = VirtualUser.new
        vu.is_admin = true
        vu.user = params[:username]
        vu.domain_id = vd.id
        vu.password = hash_pass(params[:password])

        vu.save rescue error!("Error creating user :S", 400)

        {ok: 1}
      end
    end


    resource :invite do
      desc 'Create a new invite'
      params do
        requires :email, type: String, desc: 'Your email'
      end
      post do
        emailstr = params[:email]
        email = emailstr.split("@")

        from = VirtualUser.join(VirtualDomain, id: :domain_id).
          where(name: email[1]).
          where(user: email[0]).first

        error!("No such email", 400) unless from
        domain_id = from[:domain_id] # No cross-domain invites

        # User exists. Create an invite for this domain and send it to them
        invite_code = SecureRandom.hex(20)
        invite = Invite.new

        invite.from = from.id
        invite.code = invite_code
        invite.domain_id = domain_id
        invite.save rescue error!("Error creating invite! Sorry")

        # Now email the invite to the user so they can pass it on to whoever
        mail = Mail.new do
          from conf["signup_from"]
          to emailstr
          subject conf["subject"]
        end
        mail[:body] = <<EOM
Someone has requested an invite code with your address.
If this was not you, please go here: #{conf["signup_delete_url"] + "?invite=" + invite_code + "&domain=" + domain_id.to_s} to remove it.

If it was you, please provide the link below to the person who wants to signup.
Please recall that this works on a system of trust. Only invite a person whom you
feel sure will not abuse the service. Spam will not be tolerated.
#{conf["signup_url"] + '?invite='+invite_code+'&domain='+domain_id.to_s}

Best,
#{conf["signup_signame"]}
EOM
        mail.delivery_method :sendmail
        mail.deliver! rescue "Unable to deliver the invite email; please contact the admin and/or try again later"
        {ok: 1} # we hope
      end
    end
  end
end

