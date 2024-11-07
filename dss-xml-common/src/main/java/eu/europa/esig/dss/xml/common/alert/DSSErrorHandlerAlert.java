/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xml.common.alert;

import eu.europa.esig.dss.alert.AbstractAlert;
import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.xml.common.DSSErrorHandler;
import eu.europa.esig.dss.xml.common.exception.XSDValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXParseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The default {@code DSSErrorHandler} alert.
 * Throws a {@code XSDValidationException} containing a list of error messages if applicable.
 *
 */
public class DSSErrorHandlerAlert extends AbstractAlert<DSSErrorHandler> {

	private static final Logger LOG = LoggerFactory.getLogger(DSSErrorHandlerAlert.class);

	/** The default error message */
	private static final String ERROR_MESSAGE = "Error during the XML schema validation : {}";

	/**
	 * Indicates whether warning messages should be reported within the error list
	 */
	private boolean enableWarnings = false;

	/**
	 * Indicates whether the position (line and column number) of the failed condition
	 * should be reported within the error list
	 */
	private boolean enablePosition = false;

	/**
	 * The default constructor
	 */
	public DSSErrorHandlerAlert() {
		// empty constructor
	}

	/**
	 * Sets whether validation warnings shall be returned within the error list
	 * Default : FALSE (warnings a logged, but not returned)
	 *
	 * @param enableWarnings whether validation warnings shall be returned
	 */
	public void setEnableWarnings(boolean enableWarnings) {
		this.enableWarnings = enableWarnings;
	}

	/**
	 * Sets whether position (line and column number) of the error shall be extracted into returned validation messages
	 * NOTE :    an instance of {@code javax.xml.transform.stream.StreamSource} shall be provided to the validation,
	 *           in order to ensure the position is being extracted (e.g. will not work for {@code javax.xml.transform.dom.DOMSource}).
	 * Default : FALSE (line and column numbers are not returned)
	 *
	 * @param enablePosition whether position (line and column number) shall be returned
	 */
	public void setEnablePosition(boolean enablePosition) {
		this.enablePosition = enablePosition;
	}

	@Override
	protected AlertDetector<DSSErrorHandler> getAlertDetector() {
		return errorHandler -> !errorHandler.isValid();
	}

	@Override
	protected AlertHandler<DSSErrorHandler> getAlertHandler() {
		return new AlertHandler<DSSErrorHandler>() {

			@Override
			public void process(DSSErrorHandler errorHandler) {
				List<SAXParseException> exceptions = new ArrayList<>();

				exceptions.addAll(getFatalErrors(errorHandler));
				exceptions.addAll(getErrors(errorHandler));
				exceptions.addAll(getWarnings(errorHandler));

				List<String> messages = processExceptions(exceptions);

				XSDValidationException xsdValidationException = new XSDValidationException(messages);
				exceptions.forEach(xsdValidationException::addSuppressed);

				throw xsdValidationException;
			}

			private List<SAXParseException> getFatalErrors(DSSErrorHandler errorHandler) {
				return errorHandler.getFatalErrors();
			}

			private List<SAXParseException> getErrors(DSSErrorHandler errorHandler) {
				return errorHandler.getErrors();
			}

			private List<SAXParseException> getWarnings(DSSErrorHandler errorHandler) {
				if (enableWarnings) {
					return errorHandler.getWarnings();
				} else if (LOG.isDebugEnabled()) {
					for (SAXParseException warningException : errorHandler.getWarnings()) {
						LOG.debug(getValidationMessage(warningException));
					}
				}
				return Collections.emptyList();
			}

			private List<String> processExceptions(List<SAXParseException> exceptions) {
				List<String> messages = new ArrayList<>();
				for (SAXParseException exception : exceptions) {
					String validationMessage = getValidationMessage(exception);
					LOG.warn(ERROR_MESSAGE, validationMessage);
					messages.add(validationMessage);
				}
				return messages;
			}

		};
	}

	/**
	 * Builds a validation message from {@code SAXParseException}
	 *
	 * @param e {@link SAXParseException} containing information about a failed condition
	 * @return {@link String} user-friendly validation message
	 */
	protected String getValidationMessage(SAXParseException e) {
		String message = e.getMessage();
		if (enablePosition) {
			message = String.format("%s (Line: %s, Column: %s)", message, e.getLineNumber(), e.getColumnNumber());
		}
		return message;
	}

}
