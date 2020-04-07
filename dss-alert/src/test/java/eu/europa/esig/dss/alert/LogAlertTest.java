package eu.europa.esig.dss.alert;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.alert.handler.LogHandler;
import eu.europa.esig.dss.alert.status.Status;

public class LogAlertTest {
	
	private static final String EXCEPTION_MESSAGE = "Bye World!";
	
	@Test
	public void warnLogAlertTest() {
		Status exception = new Status(EXCEPTION_MESSAGE);
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<Status>(Level.WARN);
		
		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<Status>(Arrays.asList(callback, logExceptionAlertHandler));
		
		CustomStatusAlert exceptionAlert = new CustomStatusAlert(alertHandler);
		exceptionAlert.alert(exception);
		
		assertTrue(callback.called);
	}
	
	@Test
	public void errorLogAlertTest() {
		Status exception = new Status(EXCEPTION_MESSAGE);
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<Status>(Level.ERROR);
		
		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<Status>(Arrays.asList(callback, logExceptionAlertHandler));
		
		CustomStatusAlert exceptionAlert = new CustomStatusAlert(alertHandler);
		exceptionAlert.alert(exception);
		
		assertTrue(callback.called);
	}
	
	@Test
	public void dssLogAlertTest() {
		Status exception = new Status(EXCEPTION_MESSAGE);
		
		// manual testing
		LogOnStatusAlert dssLogAlert = new LogOnStatusAlert(Level.INFO);
		dssLogAlert.alert(exception);
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
