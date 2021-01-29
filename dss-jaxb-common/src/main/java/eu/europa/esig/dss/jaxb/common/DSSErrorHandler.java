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

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import java.util.ArrayList;
import java.util.List;

/**
 * The default {@code ErrorHandler} used to collect the occurred during 
 * the validation errors
 *
 */
public class DSSErrorHandler implements ErrorHandler {

	/** List of error exceptions */
	private final List<SAXException> errors = new ArrayList<>();

	/** List of fatal error exceptions */
	private final List<SAXException> fatalErrors = new ArrayList<>();

	/** List of warning exceptions */
	private final List<SAXException> warnings = new ArrayList<>();

	@Override
	public void error(SAXParseException arg0) throws SAXException {
		errors.add(arg0);
	}

	@Override
	public void fatalError(SAXParseException arg0) throws SAXException {
		fatalErrors.add(arg0);
	}

	@Override
	public void warning(SAXParseException arg0) throws SAXException {
		warnings.add(arg0);
	}

	/**
	 * Returns a list of errors occurred during the validation process. An empty
	 * list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getErrors() {
		return errors;
	}

	/**
	 * Returns a list of fatal errors occurred during the validation process. An
	 * empty list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getFatalErrors() {
		return fatalErrors;
	}

	/**
	 * Returns a list of warnings occurred during the validation process. An empty
	 * list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getWarnings() {
		return warnings;
	}

	/**
	 * Checks if the validation succeeded (no errors or warning received)
	 * 
	 * @return TRUE if validation succeed, FALSE otherwise
	 */
	public boolean isValid() {
		return errors.isEmpty() && fatalErrors.isEmpty() && warnings.isEmpty();
	}

}
