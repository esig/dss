package eu.europa.esig.dss.jaxb;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;

public class SchemaFactoryBuilderTest {
	
	@Test
	public void buildTest() {
		SchemaFactoryBuilder schemaBuilder = SchemaFactoryBuilder.getSecureSchemaBuilder();
		schemaBuilder.build();
	}
	
	@Test
	public void exceptionAlertTest() {
		SchemaFactoryBuilder schemaBuilder = SchemaFactoryBuilder.getSecureSchemaBuilder();
		
		schemaBuilder.enableFeature("CUSTOM_FEATURE");
		
		schemaBuilder.setSecurityExceptionAlert(new ExceptionOnStatusAlert());
		
		Exception exception = assertThrows(AlertException.class, () -> schemaBuilder.build());
		assertNotNull(exception);
		assertTrue(exception.getMessage().contains("SECURITY : unable to set feature(s)"));
		assertTrue(exception.getMessage().contains("CUSTOM_FEATURE"));
	}

}
