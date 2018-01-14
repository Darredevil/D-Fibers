/+ dub.sdl:
	name "hello-vibed"
    dependency "vibe-d" version="~>0.8.2"
    versions "VibeDefaultMain"
+/
import vibe.d;

void serve(HTTPServerRequest req, HTTPServerResponse res)
{
	res.writeBody("Hello, world!");
}

shared static this()
{
	auto router = new URLRouter;
	router.get("/", &serve);
	
	auto settings = new HTTPServerSettings;
	settings.port = 8080;
	
	listenHTTP(settings, router);
}
