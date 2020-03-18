package eu.europa.esig.dss.jaxb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.ExceptionAlert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.jaxb.exception.XmlSecurityException;

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
		
		ThrowRuntimeExceptionAlertHandler alertHandler = new ThrowRuntimeExceptionAlertHandler();
		ExceptionAlert exceptionAlert = new ExceptionAlert(alertHandler);
		schemaBuilder.setSecurityExceptionAlert(exceptionAlert);
		
		RuntimeException exception = assertThrows(RuntimeException.class, () -> schemaBuilder.build());
		assertNotNull(exception);
		assertNotNull(exception.getCause());
		assertEquals(XmlSecurityException.class, exception.getCause().getClass());
		assertTrue(exception.getMessage().contains("SECURITY : unable to set feature 'CUSTOM_FEATURE' = 'true'."));
	}
	
	class ThrowRuntimeExceptionAlertHandler implements AlertHandler<Exception> {

		@Override
		public void process(Exception e) {
			throw new RuntimeException(e);
		}
		
	}

}
