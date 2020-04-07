package eu.europa.esig.dss.jaxb;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.AbstractStatusAlert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.alert.handler.LogHandler;
import eu.europa.esig.dss.alert.status.Status;

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
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<Status>(Level.INFO);
		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<Status>(Arrays.asList(callback, logExceptionAlertHandler));

		secureTransformerBuilder.setSecurityExceptionAlert(new CustomStatusAlert(alertHandler));
		
		secureTransformerBuilder.build();
		
		assertTrue(callback.called);
	}
	
	@Test
	public void errorLogExceptionTest() {
		TransformerFactoryBuilder secureTransformerBuilder = TransformerFactoryBuilder.getSecureTransformerBuilder();
		secureTransformerBuilder.setAttribute("CUSTOM_ATTRIBUTE", "CUSTOM_VALUE");
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<Status>(Level.ERROR);
		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<Status>(Arrays.asList(callback, logExceptionAlertHandler));
		
		secureTransformerBuilder.setSecurityExceptionAlert(new CustomStatusAlert(alertHandler));
		
		secureTransformerBuilder.build();
		
		assertTrue(callback.called);
	}
	
	class CustomStatusAlert extends AbstractStatusAlert {

		public CustomStatusAlert(AlertHandler<Status> handler) {
			super(handler);
		}

	}

	class CallbackExceptionAlertHandler implements AlertHandler<Status> {
		
		private boolean called = false;

		@Override
		public void process(Status e) {
			called = true;
		}
		
	}

}
