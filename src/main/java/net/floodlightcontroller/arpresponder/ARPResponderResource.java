package net.floodlightcontroller.arpresponder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

public class ARPResponderResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(ARPResponderResource.class);

	@Get("json")
    public List<String> retrieveSubnets() {
		IARPResponderService iarpr = (IARPResponderService)getContext().getAttributes().get(IARPResponderService.class.getCanonicalName());
        List<String> l = new ArrayList<String>();
        l.addAll(iarpr.getSubnets());
        return l;
    }
	
	/**
	 * parse a JSON string into an IPv4 Address, then add it to subnets
	 * @return A string status message
	 */
	@Post
	public String store(String fmtJson) {
		IARPResponderService iarpr =
				(IARPResponderService)getContext().getAttributes().
				get(IARPResponderService.class.getCanonicalName());

		IPv4Address ip = jsonToIp(fmtJson);
		if (ip == null) {
			return "{\"status\" : \"Error! Could not parse subnet ip.\"}";
		}
		String status = null;
		if (iarpr.getSubnets().contains(ip.toString())) {
			status = "Error! Subnet ip already exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			// add subnet to ARP Responder
			iarpr.addSubnet(ip);
			status = "Subnet added";
			return ("{\"status\" : \"" + status + "\", \"ip\" : \""+ ip.toString() + "\"}");
		}
	}
		
	private IPv4Address jsonToIp(String fmtJson) {
		System.out.println(fmtJson);
		IPv4Address ip = null;
		JsonFactory jsonfactory = new JsonFactory();
		try {
			JsonParser jp = jsonfactory.createParser(fmtJson);
			while (jp.nextToken() != JsonToken.END_OBJECT){
				String token = jp.getCurrentName();
				if ("subnet".equals(token)){
					jp.nextToken();
					ip = IPv4Address.of(jp.getText());
					break;
				} 
			}
		} catch (JsonParseException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return ip;
	}
}


