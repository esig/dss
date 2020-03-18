package eu.europa.esig.dss.jaxb;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.ExceptionAlert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.alert.handler.log.LogExceptionAlertHandler;

public class TransformerFactoryBuilderTest {
	
	@Test
	public void buildTest() {
		TransformerFactoryBuilder secureTransformerBuilder = TransformerFactoryBuilder.getSecureTransformerBuilder();
		secureTransformerBuilder.build();
	}
	
	@Test
	public void infoLogExceptionTest() {
		TransformerFactoryBuilder secureTransformerBuilder = TransformerFactoryBuilder.getSecureTransformerBuilder();
		secureTransformerBuilder.enableFeature("CUSTOM_FEATURE");
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogExceptionAlertHandler logExceptionAlertHandler = new LogExceptionAlertHandler(Level.INFO, false);
		CompositeAlertHandler<Exception> alertHandler = new CompositeAlertHandler<Exception>(Arrays.asList(callback, logExceptionAlertHandler));
		
		ExceptionAlert exceptionAlert = new ExceptionAlert(alertHandler);
		secureTransformerBuilder.setSecurityExceptionAlert(exceptionAlert);
		
		secureTransformerBuilder.build();
		
		assertTrue(callback.called);
	}
	
	@Test
	public void errorLogExceptionTest() {
		TransformerFactoryBuilder secureTransformerBuilder = TransformerFactoryBuilder.getSecureTransformerBuilder();
		secureTransformerBuilder.setAttribute("CUSTOM_ATTRIBUTE", "CUSTOM_VALUE");
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogExceptionAlertHandler logExceptionAlertHandler = new LogExceptionAlertHandler(Level.ERROR, true);
		CompositeAlertHandler<Exception> alertHandler = new CompositeAlertHandler<Exception>(Arrays.asList(callback, logExceptionAlertHandler));
		
		ExceptionAlert exceptionAlert = new ExceptionAlert(alertHandler);
		secureTransformerBuilder.setSecurityExceptionAlert(exceptionAlert);
		
		secureTransformerBuilder.build();
		
		assertTrue(callback.called);
	}
	
	class CallbackExceptionAlertHandler implements AlertHandler<Exception> {
		
		private boolean called = false;

		@Override
		public void process(Exception e) {
			called = true;
		}
		
	}

}
