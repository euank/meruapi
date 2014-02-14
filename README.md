meruapi
=======

A ruby Grape API for managing the users of a mysql-backed mail server

It only provides the api. Something else(html+js likely) has to actually
interact with the api.

Trust
-----

Spam is a massive problem with email, so allowing new account creation with no
barrier is bad. This is handled by an invite system in this case. The invites
are unlimited... There are plans to limit it or at least log it more carefully
to ensure this system is not abused. However, given that all people invited are
trustworthy, this shouldn't be a problem for a while.

