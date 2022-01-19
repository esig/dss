/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.handler.CompositeAlertHandler;
import eu.europa.esig.dss.alert.handler.LogHandler;
import eu.europa.esig.dss.alert.status.MessageStatus;
import eu.europa.esig.dss.alert.status.ObjectStatus;
import eu.europa.esig.dss.alert.status.Status;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LogAlertTest {
	
	private static final String EXCEPTION_MESSAGE = "Bye World!";
	
	@Test
	public void warnLogAlertTest() {
		MessageStatus status = new MessageStatus();
		status.setMessage(EXCEPTION_MESSAGE);
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<>(Level.WARN);
		
		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<>(Arrays.asList(callback, logExceptionAlertHandler));
		
		CustomStatusAlert exceptionAlert = new CustomStatusAlert(alertHandler);
		exceptionAlert.alert(status);
		
		assertTrue(callback.called);
	}
	
	@Test
	public void errorLogAlertTest() {
		MessageStatus status = new MessageStatus();
		status.setMessage(EXCEPTION_MESSAGE);
		
		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<>(Level.ERROR);
		
		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<>(Arrays.asList(callback, logExceptionAlertHandler));
		
		CustomStatusAlert exceptionAlert = new CustomStatusAlert(alertHandler);
		exceptionAlert.alert(status);
		
		assertTrue(callback.called);
	}
	
	@Test
	public void dssLogAlertTest() {
		MessageStatus status = new MessageStatus();
		status.setMessage(EXCEPTION_MESSAGE);
		
		// manual testing
		assertDoesNotThrow(() -> {
			LogOnStatusAlert dssLogAlert = new LogOnStatusAlert(Level.INFO);
			dssLogAlert.alert(status);
		});
	}

	@Test
	public void logAlertWithSubMessageTest() {
		ObjectStatus status = new ObjectStatus();
		status.setMessage(EXCEPTION_MESSAGE);

		String objectError = "Cannot process the object!";
		status.addRelatedObjectIdentifierAndErrorMessage("id-12345", objectError);

		CallbackExceptionAlertHandler callback = new CallbackExceptionAlertHandler();
		LogHandler<Status> logExceptionAlertHandler = new LogHandler<>(Level.WARN);

		CompositeAlertHandler<Status> alertHandler = new CompositeAlertHandler<>(Arrays.asList(callback, logExceptionAlertHandler));

		CustomStatusAlert exceptionAlert = new CustomStatusAlert(alertHandler);
		exceptionAlert.alert(status);

		assertTrue(callback.called);
	}
	
	private static class CustomStatusAlert extends AbstractStatusAlert {

		public CustomStatusAlert(AlertHandler<Status> handler) {
			super(handler);
		}

	}

	private static class CallbackExceptionAlertHandler implements AlertHandler<Status> {
		
		private boolean called = false;

		@Override
		public void process(Status e) {
			called = true;
		}
		
	}

}
