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
package eu.europa.esig.dss.jaxb;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import javax.xml.transform.TransformerFactory;

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
		TransformerFactory transformerFactory = secureTransformerBuilder.build();
		assertNotNull(transformerFactory);
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
