package eu.europa.esig.dss.alert;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.alert.status.Status;

public class ExceptionAlertTest {
	
	private static final String EXCEPTION_MESSAGE = "Bye World!";
	
	@Test
	public void throwExceptionAlertTest() {
		Status status = new Status(EXCEPTION_MESSAGE);
		
		AlertException alertException = assertThrows(AlertException.class, () -> {
			ExceptionOnStatusAlert exceptionAlert = new ExceptionOnStatusAlert();
			exceptionAlert.alert(status);
		});
		assertTrue(alertException.getMessage().contains(EXCEPTION_MESSAGE));
	}

	@Test
	public void throwNothing() {
		Status status = new Status(null);

		ExceptionOnStatusAlert exceptionAlert = new ExceptionOnStatusAlert();
		exceptionAlert.alert(status);

		assertNotNull(status);
	}

	@Test
	public void silenceMode() {
		Status status = new Status(EXCEPTION_MESSAGE);

		SilentOnStatusAlert silence = new SilentOnStatusAlert();
		silence.alert(status);

		assertNotNull(status);
	}

}
