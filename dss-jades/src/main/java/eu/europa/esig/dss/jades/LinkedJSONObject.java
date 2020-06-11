package eu.europa.esig.dss.jades;

import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jose4j.json.internal.json_simple.JSONAware;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.json.internal.json_simple.JSONStreamAware;

/**
 * Represents an ordered JSON Object by extending a LinkedHashMap
 */
public class LinkedJSONObject extends LinkedHashMap implements Map, JSONAware, JSONStreamAware {
	
	private static final long serialVersionUID = -8891417988762118707L;
	
	/**
	 * Creates an empty map
	 */
	public LinkedJSONObject() {
		super();
	}

	/**
	 * Allows creation of a LinkedJSONObject from a Map. After that, both the
	 * generated LinkedJSONObject and the Map can be modified independently.
	 * 
	 * @param map
	 */
	public LinkedJSONObject(Map map) {
		super(map);
	}

	@Override
	public void writeJSONString(Writer out) throws IOException {
		JSONObject.writeJSONString(this, out);
	}

	@Override
	public String toJSONString() {
		return JSONObject.toJSONString(this);
	}
	
	@Override
	public String toString() {
		return toJSONString();
	}

}
