import os
from pathlib import Path
import cherrypy
import base64
import hashlib

class SP(object):

	# Creates a random name just for temporarility storing an uploded file
	def random_name( self ):
		return base64.urlsafe_b64encode( os.urandom( 15 ) ).decode( 'utf8' )

	# Reads a static HTML page
	def static_page( self, path ):
		return open( 'static/' + path, 'r' ).read()

	# Checks if the request comes with an account cookie
	# This code is unsafe (the cookie can be forged!)
	def get_account( self, redirect ):
		cookies = cherrypy.request.cookie
		if not cookies:
			if redirect:
				raise cherrypy.HTTPRedirect( '/login', status=307 )
			else:
			    return False
		username = cookies['username'].value
		self.set_cookie( username ) # for keeping the session alive
		return username

	# Create a session cookie (insecure, can be forged)
	# The validity is short by design, to force authentications
	def set_cookie( self, username ):
		cookie = cherrypy.response.cookie
		cookie['username'] = username
		cookie['username']['path'] = '/'
		cookie['username']['max-age'] = '20'
		cookie['username']['version'] = '1'

	# Present the account images and an upload form
	def account_contents( self, account ):
		contents = '<html><body>'
		contents += '<p>Upload a new image file</p>'
		contents += '<form action="add" method="post" enctype="multipart/form-data">'
		contents += '<input type="file" name="image" /><br>'
		contents += '<input type="submit" value="send" />'
		contents += '</form>'
		contents += '<form action="add" method="post" enctype="multipart/form-data">'
		contents += '<p>List of uploaded image file</sp>'
		contents += '<table border=0><tr>'
		
		path = 'accounts/' + account
		files = os.listdir( path )
		count = 0
		for f in files:
			contents += '<td><img src="/img?name=' + f + '"></td>'
			count += 1
			if count % 4 == 0:
				contents += '</tr><tr>'
		contents += '</tr></body></html>'
		return contents

	# Root HTTP server method
	@cherrypy.expose
	def index(self):
		account = self.get_account( True )

		if not os.path.exists( 'accounts' ):
			os.mkdir( 'accounts', 666 )
		path = 'accounts/' + account
		if not os.path.exists( path ):
			os.mkdir( path, 666 )
		raise cherrypy.HTTPRedirect( '/account', status=307 )

	# Login page, which performs a (visible) HTML redirection
	@cherrypy.expose
	def login(self):
		return self.static_page( 'login.html' )
	
	# Identity provisioning by an IdP
	@cherrypy.expose
	def identity(self, username):
		self.set_cookie( username )
		raise cherrypy.HTTPRedirect( '/', status=307 )

	# Expose account page
	@cherrypy.expose
	def account(self):
		account = self.get_account( True )
		return self.account_contents( account )

	# Get individual account image
	@cherrypy.expose
	def img(self, name):
		account = self.get_account( True )
		path = os.getcwd() + '/accounts/' + account + "/" + name
		return cherrypy.lib.static.serve_file( path, content_type='jpg' );

	# Upload new image for an account
	@cherrypy.expose
	def add(self, image):
		name = self.random_name() 
		account = self.get_account( False )
		if not account:
			return self.static_page( 'login.html' );

		path = Path( os.getcwd() + '/accounts/' + account + "/" + name )
		m = hashlib.sha1()
		with path.open( 'wb' ) as new_file:
			while True:
				data = image.file.read( 8192 )
				if not data:
					break
				new_file.write( data )
				m.update( data )

		name = base64.urlsafe_b64encode( m.digest()[0:18] ).decode( 'utf8' )
		new_path = Path( os.getcwd() + '/accounts/' + account + "/" + name )
		if not new_path.exists():
		    path.rename( new_path )
		else:
		    path.unlink( missing_ok=True )

		return self.account_contents( account )

cherrypy.config.update( {'server.socket_host': '127.0.0.1',
						 'server.socket_port': 8081 } )
cherrypy.quickstart( SP() )
