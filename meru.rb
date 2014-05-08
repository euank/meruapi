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
    @conf = JSON.parse(File.read("config.json"))
    dbconf = @conf["database"]
    DB = Sequel.connect(adapter: :mysql, host: dbconf["host"],
                        database: dbconf["database"],
                        user: dbconf["username"],
                        password: dbconf["password"])

    class Invite < Sequel::Model; end
    class VirtualUser < Sequel::Model; end
    class VirtualAlias < Sequel::Model; end
    class VirtualDomain < Sequel::Model; end


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
            user.password = password.crypt('$6$' + SecureRandom.hex(16))
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
        validate_pass(params[:newpassword]) || error!("Invalid new pass", 400)

        user = VirtualUser.join(VirtualDomain, id: :domain_id).
          where(name: email[1]).
          where(user: email[0]).first

        error!("Invalid user") unless user

        # Check their old password is right
        magic, salt = user[:password].split('$')[1,2]
        oldpass.crypt("$#{magic}$#{salt}") == user[:password] || error!("Invalid password")

        # Update em
        user.password = newpass.crypt('$6$' + SecureRandom.hex(16))
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


    resource :invite do
      desc 'Create a new invite'
      params do
        requires :email, type: String, desc: 'Your email'
      end
      post do
        email = params[:email].split("@").map{|x| client.escape(x)}

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

