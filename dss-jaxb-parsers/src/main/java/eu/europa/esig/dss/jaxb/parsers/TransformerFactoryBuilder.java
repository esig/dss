package eu.europa.esig.dss.jaxb.parsers;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;

public class TransformerFactoryBuilder extends AbstractFactoryBuilder<TransformerFactory> {
	
	private TransformerFactoryBuilder() {
		enableFeature(XMLConstants.FEATURE_SECURE_PROCESSING);
		setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
	}
	
	/**
	 * Instantiates a pre-configured with security features {@code TransformerFactoryBuilder}
	 * 
	 * @return default {@link TransformerFactoryBuilder}
	 */
	public static TransformerFactoryBuilder getSecureTransformerBuilder() {
		return new TransformerFactoryBuilder();
	}
	
	/**
	 * Builds the configured {@code TransformerFactory}
	 * 
	 * @return {@link TransformerFactory}
	 */
	public TransformerFactory build() {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		setSecurityFeatures(transformerFactory);
		setSecurityAttributes(transformerFactory);
		return transformerFactory;
	}
	
	@Override
	public TransformerFactoryBuilder enableFeature(String feature) {
		return (TransformerFactoryBuilder) super.enableFeature(feature);
	}
	
	@Override
	public TransformerFactoryBuilder disableFeature(String feature) {
		return (TransformerFactoryBuilder) super.disableFeature(feature);
	}
	
	@Override
	public TransformerFactoryBuilder setAttribute(String attribute, Object value) {
		return (TransformerFactoryBuilder) super.setAttribute(attribute, value);
	}
	
	@Override
	public TransformerFactoryBuilder removeAttribute(String attribute) {
		return (TransformerFactoryBuilder) super.removeAttribute(attribute);
	}

	@Override
	protected void setSecurityFeature(TransformerFactory factory, String feature, Boolean value) throws Exception {
		factory.setFeature(feature, value);
	}

	@Override
	protected void setSecurityAttribute(TransformerFactory factory, String attribute, Object value) throws IllegalArgumentException {
		factory.setAttribute(attribute, value);
	}

}
