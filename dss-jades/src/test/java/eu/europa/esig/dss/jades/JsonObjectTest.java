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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.junit.jupiter.api.Test;

class JsonObjectTest {
	
	@Test
	void orderTest() {
		LinkedHashMap<String, Object> linkedHashMap = new LinkedHashMap<>();
		linkedHashMap.put("key1", "value1");
		linkedHashMap.put("key2", "value2");
		linkedHashMap.put("key3", "value3");
		linkedHashMap.put("key4", "value4");
		linkedHashMap.put("key5", "value5");
		linkedHashMap.put("key6", "value6");
		JsonObject jsonObject = new JsonObject(linkedHashMap);
		
		Set<Map.Entry<String, Object>> entrySet = jsonObject.entrySet();
		Iterator<Map.Entry<String, Object>> iterator = entrySet.iterator();
		int i = 0;
		while (iterator.hasNext()) {
			++i;
			String keyName = "key" + i;
			Map.Entry<String, Object> entry = iterator.next();
			assertEquals(keyName, entry.getKey());
		}
		assertEquals(linkedHashMap.size(), i);
	}
	
	@Test
	void compareTest() {
		LinkedHashMap<String, Object> linkedHashMap = new LinkedHashMap<>();
		linkedHashMap.put("header", "fh43hq94gf3j9o");
		
		JSONObject jsonObject = new JSONObject(linkedHashMap);
		JsonObject dssJsonObject = new JsonObject(linkedHashMap);
		assertEquals(jsonObject.toJSONString(), dssJsonObject.toJSONString());
	}

}
