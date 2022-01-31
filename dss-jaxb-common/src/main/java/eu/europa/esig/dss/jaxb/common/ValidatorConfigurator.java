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

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.jaxb.common.exception.SecurityConfigurationException;
import org.xml.sax.ErrorHandler;

import javax.xml.XMLConstants;
import javax.xml.validation.Validator;
import java.util.Objects;

/**
 * Configures a provided {@code Validator}
 *
 */
public class ValidatorConfigurator extends AbstractConfigurator<Validator> {

	/**
	 * The alert used to process the errors collected during the validation process
	 * 
	 * Default : {@code DSSErrorHandlerAlert} - collects exception and throws {@code XSDValidationException}
	 */
	private Alert<DSSErrorHandler> errorHandlerAlert = new DSSErrorHandlerAlert();

	/**
	 * Default constructor
	 */
	protected ValidatorConfigurator() {
		// The configuration protects against XXE
		// (https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#validator)
		setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
	}
	
	/**
	 * Instantiates a pre-configured with security features {@code ValidatorConfigurator}
	 * 
	 * @return default {@link ValidatorConfigurator}
	 */
	public static ValidatorConfigurator getSecureValidatorConfigurator() {
		return new ValidatorConfigurator();
	}
	
	/**
	 * Configures the {@code javax.xml.validation.Validator} by setting the
	 * pre-defined features and attributes
	 * 
	 * @param validator {@link javax.xml.validation.Validator} to be configured
	 */
	public void configure(Validator validator) {
		Objects.requireNonNull(validator, "Validator must be provided");
		setSecurityFeatures(validator);
		setSecurityAttributes(validator);
		setErrorHandler(validator);
	}
	
	@Override
	public ValidatorConfigurator enableFeature(String feature) {
		return (ValidatorConfigurator) super.enableFeature(feature);
	}
	
	@Override
	public ValidatorConfigurator disableFeature(String feature) {
		return (ValidatorConfigurator) super.disableFeature(feature);
	}

	/**
	 * Sets {@code Alert<DSSErrorHandler>} used to process the collected exception
	 * during the XML file validation
	 * 
	 * @param errorHandlerAlert {@link Alert} to handle the {@link DSSErrorHandler}
	 */
	public void setErrorHandlerAlert(Alert<DSSErrorHandler> errorHandlerAlert) {
		Objects.requireNonNull(errorHandlerAlert, "errorHandlerAlert cannot be null!");
		this.errorHandlerAlert = errorHandlerAlert;
	}
	
	@Override
	public ValidatorConfigurator setAttribute(String attribute, Object value) {
		return (ValidatorConfigurator) super.setAttribute(attribute, value);
	}
	
	@Override
	public ValidatorConfigurator removeAttribute(String attribute) {
		return (ValidatorConfigurator) super.removeAttribute(attribute);
	}

	@Override
	protected void setSecurityFeature(Validator validator, String feature, Boolean value) throws SecurityConfigurationException {
		try {
			validator.setFeature(feature, value);
		} catch (Exception e) {
			throw new SecurityConfigurationException(e);
		}
	}

	@Override
	protected void setSecurityAttribute(Validator validator, String attribute, Object value) throws SecurityConfigurationException {
		try {
			validator.setProperty(attribute, value);
		} catch (Exception e) {
			throw new SecurityConfigurationException(e);
		}
	}

	/**
	 * Sets {@code DSSErrorHandler} in order to collect exceptions occurred during
	 * the validation process
	 * 
	 * @param validator {@link javax.xml.validation.Validator}
	 */
	protected void setErrorHandler(Validator validator) {
		validator.setErrorHandler(new DSSErrorHandler());
	}

	/**
	 * Handles the validation errors occurred during an XML file validation
	 * 
	 * @param validator {@link javax.xml.validation.Validator}
	 */
	public void postProcess(Validator validator) {
		ErrorHandler errorHandler = validator.getErrorHandler();
		if (errorHandler instanceof DSSErrorHandler) {
			errorHandlerAlert.alert((DSSErrorHandler) errorHandler);
		}
	}

}
