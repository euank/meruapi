meruapi
=======

A ruby Grape API for managing the users of a postgres-backed mail server.

It makes the assumption that your DB schema is akin to the one used by
iRedMail-0.8.7 if you select postgresql as your database scheme. It also will
modify the scheme (oh so minorly) by creating a new table named "invites".

It only provides the api. Something else(html+js likely) has to actually
interact with the api.

Trust
-----

Spam is a massive problem with email, so allowing new account creation with no
barrier is bad. This is handled by an invite system in this case. The invites
are unlimited... There are plans to limit it or at least log it more carefully
to ensure this system is not abused. However, given that all people invited are
trustworthy, this shouldn't be a problem for a while.

