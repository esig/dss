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

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;

/**
 * Builds a {@code TransformerFactory}
 */
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
