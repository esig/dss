package eu.europa.esig.dss.alert;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.handler.AlertHandler;

public class ExceptionAlertTest {
	
	private static final String EXCEPTION_MESSAGE = "Bye World!";
	
	@Test
	public void throwExceptionAlertTest() {
		Exception exception = new Exception(EXCEPTION_MESSAGE);
		
		ThrowRuntimeExceptionAlertHandler throwRuntimeExceptionAlertHandler = new ThrowRuntimeExceptionAlertHandler();
		
		RuntimeException runtimeException = assertThrows(RuntimeException.class, () -> {
			ExceptionAlert exceptionAlert = new ExceptionAlert(throwRuntimeExceptionAlertHandler);
			exceptionAlert.alert(exception);
		});
		assertTrue(runtimeException.getMessage().contains(EXCEPTION_MESSAGE));
	}
	
	class ThrowRuntimeExceptionAlertHandler implements AlertHandler<Exception> {

		@Override
		public void process(Exception e) {
			if (e instanceof RuntimeException) {
				throw (RuntimeException) e;
			} else {
				throw new RuntimeException(e);
			}
		}
		
	}

}
