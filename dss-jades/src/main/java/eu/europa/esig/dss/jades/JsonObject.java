package eu.europa.esig.dss.jades;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONObject;

/**
 * Represents a wrapper of a Map with JsonObject methods
 */
public class JsonObject implements Map, Serializable {
	
	private static final long serialVersionUID = -8891417988762118707L;
	
	private Map map;
	
	/**
	 * Creates an empty HashMap
	 */
	public JsonObject() {
		map = new HashMap<>();
	}

	/**
	 * Wraps a provided Map to the object
	 * 
	 * @param m {@link Map} to wrap
	 */
	public JsonObject(Map m) {
		Objects.requireNonNull("Map cannot be null!");
		map = m;
	}

	/**
	 * Converts the object to its JSON String representation
	 * 
	 * @return {@link String} JSON
	 */
	public String toJSONString() {
		return JSONObject.toJSONString(map);
	}

	@Override
	public int size() {
		return map.size();
	}

	@Override
	public boolean isEmpty() {
		return map.isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		return map.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		return map.containsValue(value);
	}

	@Override
	public Object get(Object key) {
		return map.get(key);
	}

	@Override
	public Object put(Object key, Object value) {
		return map.put(key, value);
	}

	@Override
	public Object remove(Object key) {
		return map.remove(key);
	}

	@Override
	public void putAll(Map m) {
		map.putAll(m);
	}

	@Override
	public void clear() {
		map.clear();
	}

	@Override
	public Set keySet() {
		return map.keySet();
	}

	@Override
	public Collection values() {
		return map.values();
	}

	@Override
	public Set entrySet() {
		return map.entrySet();
	}
	
	@Override
	public String toString() {
		return toJSONString();
	}

}
