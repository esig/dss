/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jose4j.json.JsonUtil;

/**
 * Represents a wrapper of a Map with JsonObject methods
 */
public class JsonObject implements Map<String, Object> {
	
	private Map<String, Object> map;
	
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
	public JsonObject(Map<String, Object> m) {
		Objects.requireNonNull("Map cannot be null!");
		map = m;
	}

	/**
	 * Converts the object to its JSON String representation
	 * 
	 * @return {@link String} JSON
	 */
	public String toJSONString() {
		return JsonUtil.toJson(map);
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
	public Object put(String key, Object value) {
		return map.put(key, value);
	}

	@Override
	public Object remove(Object key) {
		return map.remove(key);
	}

	@Override
	public void putAll(Map<? extends String, ? extends Object> m) {
		map.putAll(m);
	}

	@Override
	public void clear() {
		map.clear();
	}

	@Override
	public Set<String> keySet() {
		return map.keySet();
	}

	@Override
	public Collection<Object> values() {
		return map.values();
	}

	@Override
	public Set<Map.Entry<String, Object>> entrySet() {
		return map.entrySet();
	}
	
	@Override
	public String toString() {
		return toJSONString();
	}

}
