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
    mail_conf = conf["mail"]
    dbconf = conf["database"]
    DB = Sequel.connect(adapter: :postgres, host: dbconf["host"],
                        database: dbconf["database"],
                        user: dbconf["username"],
                        password: dbconf["password"])

    # Created by iRedMail
    class Mailbox < Sequel::Model(DB[:mailbox]); end
    class Alias < Sequel::Model(DB[:alias]); end
    class Domain < Sequel::Model(DB[:domain]); end


    class Invite < Sequel::Model; end
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
        s.username
      end

      def valid_domain(domain)
        !!Domain.where(domain: domain).first
      end

      def email_taken(email)
        Mailbox.where(username: email).first || Alias.where(address: email).first
      end

      def generate_maildir(email)
        username, domain = email.split('@')
        timestamp = Time.now.strftime('-%Y.%m.%d.%H.%M.%S')
        maildir = ''
        if username.size >= 3
          maildir = File.join(username[0], username[1], username[2], username+'-'+timestamp)
        elsif username.size == 2
          maildir = File.join(username[0], username[1], username[1], username+'-'+timestamp)
        else
          maildir = File.join(username[0], username[0], username[0], username+'-'+timestamp)
        end

        File.join(domain, maildir)
      end
    end

    resource :account do
      desc 'Creates an account'
      params do
        requires :user, type: String, desc: 'Username'
        requires :password, type: String, desc: 'Password'
        requires :invite, type: String, desc: 'Invite code'
        requires :domain, type: String, desc: 'Domain'
      end
      post do
        uname = params[:user].downcase.strip
        password = params[:password]
        invite = params[:invite]
        domain = params[:domain]

        error!("Invalid username", 400) unless valid_name(uname)
        error!("Invalid domain", 400) unless valid_domain(domain)

        email = uname+'@'+domain

        # Make sure the email is new
        error!("Email in use", 400) if email_taken(email)

        error!("Invalid password", 400) unless valid_pass(password)

        begin
          DB.transaction do
            invite = Invite.where("code = ? AND domain = ? AND status IS NULL",
                                      invite, domain).first
            raise "Invalid invite" unless invite


            mailbox = Mailbox.new
            mailbox.username = email
            mailbox.domain = domain
            mailbox.password = hash_pass(password)
            mailbox.storagebasedirectory = mail_conf['storage_base_directory']
            mailbox.storagenode = mail_conf['storage_node']
            mailbox.name = ''
            mailbox.maildir = generate_maildir(email)
            mailbox.quota = 0
            mailbox.created = Time.now
            mailbox.active = '1'
            mailbox.local_part = uname
            mailbox.save

            ali = Alias.new
            ali.address = email
            ali.goto = email
            ali.domain = domain
            ali.created = Time.now
            ali.active = '1'
            ali.save


            invite.status = 1 # used
            invite.to = email
            invite.consumed_at = Time.now
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
	email = params[:email]
        user = Mailbox.where(username: email).first
        error!("Invalid password", 404) unless user
        hash = user.password
        check_pass(params[:password], hash) || error!("Invalid password", 404)

        # Pass is okay, let's make them a session
        # Delete existing sessions
        LoginSession.where(username: email).delete
        session = LoginSession.new
        session.username = email
        session.session = SecureRandom.hex(50)[0...50]
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
        email = params[:email]
        oldpass = params[:oldpassword]
        newpass = params[:newpassword]
        valid_pass(params[:newpassword]) || error!("Invalid new pass", 400)

        user = Mailbox.where(username: email).first rescue nil

        error!("Invalid user") unless user

        # Check their old password is right
        check_pass(oldpass, user[:password]) || error!("Invalid password")

        # Update em
        user.password = hash_pass(newpass)
        user.save
        {ok: 1}
      end
    end


    resource :invite do
      desc 'Create a new invite'
      params do
        requires :email, type: String, desc: 'Your email'
      end
      post do
        email = params[:email]

        user = Mailbox.where(username: email).first

        error!("No such email", 400) unless user

        # User exists. Create an invite for this domain and send it to them
        invite_code = SecureRandom.hex(20)
        invite = Invite.new

        invite.from = user.username
        invite.code = invite_code
        invite.domain = email.split('@').last
        invite.created_at = Time.now
        invite.save rescue error!("Error creating invite! Sorry")

        # Now email the invite to the user so they can pass it on to whoever
        mail = Mail.new do
          from conf["signup_from"]
          to email
          subject conf["subject"]
        end
        mail[:body] = <<EOM
Someone has requested an invite code with your address.
If this was not you, please go here: #{conf["signup_delete_url"] + "?invite=" + invite_code + "&domain=" + invite.domain} to remove it.

If it was you, please provide the link below to the person who wants to signup.
Please recall that this works on a system of trust. Only invite a person whom you
feel sure will not abuse the service. Spam will not be tolerated.
#{conf["signup_url"] + '?invite='+invite_code+'&domain='+invite.domain}

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

