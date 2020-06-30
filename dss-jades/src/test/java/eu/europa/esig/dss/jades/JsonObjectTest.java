package eu.europa.esig.dss.jades;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.junit.jupiter.api.Test;

public class JsonObjectTest {
	
	@Test
	public void orderTest() {
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
	public void compareTest() {
		LinkedHashMap<String, Object> linkedHashMap = new LinkedHashMap<>();
		linkedHashMap.put("header", "fh43hq94gf3j9o");
		
		JSONObject jsonObject = new JSONObject(linkedHashMap);
		JsonObject dssJsonObject = new JsonObject(linkedHashMap);
		assertEquals(jsonObject.toJSONString(), dssJsonObject.toJSONString());
	}

}
