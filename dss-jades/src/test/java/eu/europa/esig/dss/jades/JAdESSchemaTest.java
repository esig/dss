package eu.europa.esig.dss.jades;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.Test;

public class JAdESSchemaTest {

	// https://github.com/everit-org/json-schema

	@Test
	public void test() throws IOException {
		try (InputStream inputStream = new FileInputStream("src/test/resources/esi001982-schema-draft07_v004.json")) {
			JSONObject rawSchema = new JSONObject(new JSONTokener(inputStream));

			SchemaLoader loader = SchemaLoader.builder().schemaJson(rawSchema).draftV7Support().build();
			Schema schema = loader.load().build();

			assertNotNull(schema);
		}
	}
}
