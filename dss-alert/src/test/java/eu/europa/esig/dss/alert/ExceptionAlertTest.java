package eu.europa.esig.dss.alert;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.exception.AlertException;

public class ExceptionAlertTest {
	
	private static final String EXCEPTION_MESSAGE = "Bye World!";
	
	@Test
	public void throwExceptionAlertTest() {
		Exception exception = new Exception(EXCEPTION_MESSAGE);
		
		AlertException alertException = assertThrows(AlertException.class, () -> {
			DSSExceptionAlert exceptionAlert = new DSSExceptionAlert();
			exceptionAlert.alert(exception);
		});
		assertTrue(alertException.getMessage().contains(EXCEPTION_MESSAGE));
	}

}
