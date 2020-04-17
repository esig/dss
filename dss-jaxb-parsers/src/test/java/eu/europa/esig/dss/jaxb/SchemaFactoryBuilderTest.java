package eu.europa.esig.dss.jaxb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.xml.validation.SchemaFactory;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.DSSExceptionAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.jaxb.exception.XmlSecurityException;

public class SchemaFactoryBuilderTest {
	
	@Test
	public void buildTest() {
		SchemaFactoryBuilder schemaBuilder = SchemaFactoryBuilder.getSecureSchemaBuilder();
		SchemaFactory schemaFactory = schemaBuilder.build();
		assertNotNull(schemaFactory);
	}
	
	@Test
	public void exceptionAlertTest() {
		SchemaFactoryBuilder schemaBuilder = SchemaFactoryBuilder.getSecureSchemaBuilder();
		
		schemaBuilder.enableFeature("CUSTOM_FEATURE");
		
		DSSExceptionAlert exceptionAlert = new DSSExceptionAlert();
		schemaBuilder.setSecurityExceptionAlert(exceptionAlert);
		
		Exception exception = assertThrows(AlertException.class, () -> schemaBuilder.build());
		assertNotNull(exception);
		assertNotNull(exception.getCause());
		assertEquals(XmlSecurityException.class, exception.getCause().getClass());
		assertTrue(exception.getMessage().contains("SECURITY : unable to set feature 'CUSTOM_FEATURE' = 'true'."));
	}

}
