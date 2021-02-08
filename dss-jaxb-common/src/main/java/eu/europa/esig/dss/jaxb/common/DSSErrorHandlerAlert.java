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
package eu.europa.esig.dss.jaxb.common;

import eu.europa.esig.dss.alert.AbstractAlert;
import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.jaxb.common.exception.XSDValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import java.util.ArrayList;
import java.util.List;

/**
 * The default {@code DSSErrorHandler} alert
 * 
 * Throws a {@code XSDValidationException} containing a list of errors and
 * fatalErrors if occurred
 *
 */
public final class DSSErrorHandlerAlert extends AbstractAlert<DSSErrorHandler> {

	private static final Logger LOG = LoggerFactory.getLogger(DSSErrorHandlerAlert.class);

	/** The default error message */
	private static final String ERROR_MESSAGE = "Error during the XML schema validation : {}";

	/**
	 * The default constructor
	 */
	public DSSErrorHandlerAlert() {
		super(new DSSErrorHandlerAlertDetector(), new DSSErrorHandlerAlertHandler());
	}

	private static final class DSSErrorHandlerAlertDetector implements AlertDetector<DSSErrorHandler> {

		@Override
		public boolean detect(DSSErrorHandler errorHandler) {
			return !errorHandler.isValid();
		}

	}

	private static final class DSSErrorHandlerAlertHandler implements AlertHandler<DSSErrorHandler> {

		@Override
		public void process(DSSErrorHandler errorHandler) {
			List<String> errors = new ArrayList<>();
			errors.addAll(processErrors(errorHandler.getErrors()));
			errors.addAll(processFatalErrors(errorHandler.getFatalErrors()));
			processWarnings(errorHandler.getWarnings()); // warnings are not added into the list
			throw new XSDValidationException(errors);
		}

		private List<String> processErrors(List<SAXException> exceptions) {
			List<String> messages = new ArrayList<>();
			for (SAXException exception : exceptions) {
				LOG.warn(ERROR_MESSAGE, exception.getMessage());
				messages.add(exception.getMessage());
			}
			return messages;
		}

		private List<String> processFatalErrors(List<SAXException> exceptions) {
			List<String> messages = new ArrayList<>();
			for (SAXException exception : exceptions) {
				LOG.error(ERROR_MESSAGE, exception.getMessage());
				messages.add(exception.getMessage());
			}
			return messages;
		}

		private List<String> processWarnings(List<SAXException> exceptions) {
			List<String> messages = new ArrayList<>();
			for (SAXException exception : exceptions) {
				LOG.debug(ERROR_MESSAGE, exception.getMessage());
				messages.add(exception.getMessage());
			}
			return messages;
		}

	}

}
