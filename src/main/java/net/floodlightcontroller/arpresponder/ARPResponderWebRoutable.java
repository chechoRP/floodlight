package net.floodlightcontroller.arpresponder;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class ARPResponderWebRoutable implements RestletRoutable {

	@Override
	public Restlet getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/gateways", ARPResponderResource.class);
        router.attach("/gateways/{ip}", ARPResponderResource.class);
        return router;
	}

	@Override
	public String basePath() {
		return "/arpresponder";
	}

}
