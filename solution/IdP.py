import cherrypy

class IdP(object):

	def static_contents( self, path ):
		return open( 'static/' + path, 'r' ).read()

	@cherrypy.expose
	def index(self):
            raise cherrypy.HTTPRedirect( '/authenticate', status=307 )

	@cherrypy.expose
	def authenticate(self):
            return self.static_contents( 'authenticate.html' )

	@cherrypy.expose
	def credentials(self, username):
            raise cherrypy.HTTPRedirect( "http://localhost:8081/identity?username=" + username, 307 )

cherrypy.config.update( {'server.socket_host': '127.0.0.1',
                         'server.socket_port': 8082 } )
cherrypy.quickstart( IdP() )
