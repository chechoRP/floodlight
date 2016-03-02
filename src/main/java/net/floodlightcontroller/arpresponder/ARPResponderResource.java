package net.floodlightcontroller.arpresponder;

import java.io.IOException;
import java.util.concurrent.ConcurrentMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.resource.Delete;
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
    public ConcurrentMap<String, String> retrieveGateways() {
		IARPResponderService iarpr = (IARPResponderService)getContext().getAttributes().get(IARPResponderService.class.getCanonicalName());
		return iarpr.getGateways();
    }
	
	@Delete
	public String clearGateways() {
		IARPResponderService iarpr = (IARPResponderService)getContext().getAttributes().get(IARPResponderService.class.getCanonicalName());
		iarpr.clearGateways();
		return "{\"status\" : \"Gateways Removed\"}";
    }
	
	@Delete
	public String clearGateway() {
		IARPResponderService iarpr = (IARPResponderService)getContext().getAttributes().get(IARPResponderService.class.getCanonicalName());
		String param = (String) getRequestAttributes().get("ip");
		iarpr.clearGateway(IPv4Address.of(param));
		return "{\"status\" : \"Gateway Removed\"}";
    }
	
	/**
	 * parse a JSON string into an IPv4 Address, then add it to gateways
	 * @return A string status message
	 */
	@Post
	public String store(String fmtJson) {
		IARPResponderService iarpr =
				(IARPResponderService)getContext().getAttributes().
				get(IARPResponderService.class.getCanonicalName());

		IPv4Address ip = jsonToIp(fmtJson);
		MacAddress mac = jsonToMac(fmtJson);
		if (ip == null || mac == null) {
			return "{\"status\" : \"Error! Could not parse gateway.\"}";
		}
		String status = null;
		if (iarpr.getGateways().containsKey(ip.toString())) {
			status = "Error! Gateway already exists.";
			log.error(status);
			return ("{\"status\" : \"" + status + "\"}");
		} else {
			// add gateway to ARP Responder
			iarpr.addGateway(ip, mac);
			status = "Gateway added";
			return ("{\"status\" : \"" + status + "\", \"ip\" : \""+ ip.toString() + "\"}");
		}
	}
		
	private IPv4Address jsonToIp(String fmtJson) {
		IPv4Address ip = null;
		JsonFactory jsonfactory = new JsonFactory();
		try {
			JsonParser jp = jsonfactory.createParser(fmtJson);
			while (jp.nextToken() != JsonToken.END_OBJECT){
				String token = jp.getCurrentName();
				if ("ip".equals(token)){
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
	private MacAddress jsonToMac(String fmtJson) {
		MacAddress mac = null;
		JsonFactory jsonfactory = new JsonFactory();
		try {
			JsonParser jp = jsonfactory.createParser(fmtJson);
			while (jp.nextToken() != JsonToken.END_OBJECT){
				String token = jp.getCurrentName();
				if ("mac".equals(token)){
					jp.nextToken();
					mac = MacAddress.of(jp.getText());
					break;
				} 
			}
		} catch (JsonParseException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return mac;
	}
}


