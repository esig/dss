package eu.europa.esig.dss.jaxb.parsers;

import java.util.Objects;

import javax.xml.XMLConstants;
import javax.xml.validation.Validator;

public class ValidatorConfigurator extends AbstractFactoryBuilder<Validator> {
	
	private ValidatorConfigurator() {
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
	 * Configures the {@code validator} by setting the pre-defined features and attributes
	 * 
	 * @param validator {@link Validator} to be configured
	 */
	public void configure(Validator validator) {
		Objects.requireNonNull(validator, "Validator must be provided");
		setSecurityFeatures(validator);
		setSecurityAttributes(validator);
	}
	
	@Override
	public ValidatorConfigurator enableFeature(String feature) {
		return (ValidatorConfigurator) super.enableFeature(feature);
	}
	
	@Override
	public ValidatorConfigurator disableFeature(String feature) {
		return (ValidatorConfigurator) super.disableFeature(feature);
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
	protected void setSecurityFeature(Validator validator, String feature, Boolean value) throws Exception {
		validator.setFeature(feature, value);
	}

	@Override
	protected void setSecurityAttribute(Validator validator, String attribute, Object value) throws Exception {
		validator.setProperty(attribute, value);
	}

}
