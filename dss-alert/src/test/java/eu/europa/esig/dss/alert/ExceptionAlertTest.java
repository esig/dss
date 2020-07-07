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
		
		ExceptionOnStatusAlert exceptionAlert = new ExceptionOnStatusAlert();
		AlertException alertException = assertThrows(AlertException.class, () -> exceptionAlert.alert(status));
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
