package eu.europa.esig.dss.jaxb;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;

public class SchemaFactoryBuilder extends AbstractFactoryBuilder<SchemaFactory> {
	
	private String schemaLanguage = XMLConstants.W3C_XML_SCHEMA_NS_URI;
	
	private SchemaFactoryBuilder() {
		enableFeature(XMLConstants.FEATURE_SECURE_PROCESSING);
		setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
	}
	
	/**
	 * Instantiates a pre-configured with security features {@code SchemaFactoryBuilder}
	 * 
	 * @return default {@link SchemaFactoryBuilder}
	 */
	public static SchemaFactoryBuilder getSecureSchemaBuilder() {
		return new SchemaFactoryBuilder();
	}
	
	/**
	 * Builds the configured {@code TransformerFactory}
	 * 
	 * @return {@link TransformerFactory}
	 */
	public SchemaFactory build() {
		SchemaFactory sf = SchemaFactory.newInstance(schemaLanguage);
		setSecurityFeatures(sf);
		setSecurityAttributes(sf);
		return sf;
	}
	
	/**
	 * Sets a schemaLanguage to instantiate {@code SchemaFactory} with
	 * 
	 * @param schemaLanguage {@link String} defined the schema language to use
	 */
	public void setSchemaLanguage(String schemaLanguage) {
		this.schemaLanguage = schemaLanguage;
	}
	
	@Override
	public SchemaFactoryBuilder enableFeature(String feature) {
		return (SchemaFactoryBuilder) super.enableFeature(feature);
	}
	
	@Override
	public SchemaFactoryBuilder disableFeature(String feature) {
		return (SchemaFactoryBuilder) super.disableFeature(feature);
	}
	
	@Override
	public SchemaFactoryBuilder setAttribute(String attribute, Object value) {
		return (SchemaFactoryBuilder) super.setAttribute(attribute, value);
	}
	
	@Override
	public SchemaFactoryBuilder removeAttribute(String attribute) {
		return (SchemaFactoryBuilder) super.removeAttribute(attribute);
	}

	@Override
	protected void setSecurityFeature(SchemaFactory factory, String feature, Boolean value) throws Exception {
		factory.setFeature(feature, value);
	}

	@Override
	protected void setSecurityAttribute(SchemaFactory factory, String attribute, Object value) throws Exception {
		factory.setProperty(attribute, value);
	}

}
