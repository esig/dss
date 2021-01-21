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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.status.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract class to build a secure builder instance
 *
 * @param <F> class of the object to be built
 */
public abstract class AbstractFactoryBuilder<F extends Object> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractFactoryBuilder.class);

	/** Map of features to set */
	private Map<String, Boolean> features = new HashMap<>();

	/** Map of attribute names and values to set */
	private Map<String, Object> attributes = new HashMap<>();

	/** Defines the behaviour for processing a security exception */
	private StatusAlert securityExceptionAlert = new ExceptionOnStatusAlert();

	/**
	 * This method allows to configure a custom alert on security exception in the
	 * builder
	 * 
	 * @param securityExceptionAlert {@link StatusAlert} to define
	 */
	public void setSecurityExceptionAlert(StatusAlert securityExceptionAlert) {
		Objects.requireNonNull(securityExceptionAlert);
		this.securityExceptionAlert = securityExceptionAlert;
	}
	
	/**
	 * Enables a custom feature
	 * 
	 * @param feature {@link String} the feature constraint
	 * @return this builder
	 */
	public AbstractFactoryBuilder<F> enableFeature(String feature) {
		setFeature(feature, true);
		return this;
	}

	/**
	 * Disables a custom feature
	 * 
	 * @param feature {@link String} the feature constraint
	 * @return this builder
	 */
	public AbstractFactoryBuilder<F> disableFeature(String feature) {
		setFeature(feature, false);
		return this;
	}
	
	private void setFeature(String feature, boolean value) {
		Objects.requireNonNull(feature, "The feature constraint cannot be null!");
		if (features.containsKey(feature) && features.get(feature) != value) {
			LOG.warn("SECURITY : feature with the name [{}] changed from [{}] to [{}]", feature, features.get(feature), value);
		} else if (LOG.isDebugEnabled()) {
			LOG.debug("The feature {} = {} has been added to the configuration", feature, value);
		}
		features.put(feature, value);
	}
	
	/**
	 * Sets a custom attribute.
	 * 
	 * @param attribute {@link String} attribute constraint to set
	 * @param value {@link Object} a value to define for the attribute
	 * @return this builder
	 */
	public AbstractFactoryBuilder<F> setAttribute(String attribute, Object value) {
		Objects.requireNonNull(attribute, "The attribute constraint cannot be null!");
		if (attributes.containsKey(attribute) && attributes.get(attribute).equals(value)) {
			LOG.warn("SECURITY : attribute with the name [{}] changed from [{}] to [{}]", attribute, attributes.get(attribute), value);
		} else if (LOG.isDebugEnabled()) {
			LOG.debug("The attribute {} = {} has been added to the configuration", attribute, value);
		}
		attributes.put(attribute, value);
		return this;
	}
	
	/**
	 * Removes the attribute from a list of attributes to set
	 * 
	 * @param attribute {@link String} attribute to disable
	 * @return this builder
	 */
	public AbstractFactoryBuilder<F> removeAttribute(String attribute) {
		Objects.requireNonNull(attribute, "The attribute constraint cannot be null!");
		if (attributes.containsKey(attribute)) {
			attributes.remove(attribute);
			LOG.warn("SECURITY : the attribute with name [{}] has been disabled", attribute);
		}
		return this;
	}
	
	/**
	 * Sets all features to the factory
	 *
	 * @param factory object
	 */
	protected void setSecurityFeatures(F factory) {
		List<String> messages = new ArrayList<>();
		for (Map.Entry<String, Boolean> entry : features.entrySet()) {
			try {
				setSecurityFeature(factory, entry.getKey(), entry.getValue());
			} catch (Exception e) {
				String message = String.format(
						"Feature '%s' = '%s'. Cause : %s",
						entry.getKey(), entry.getValue(), e.getMessage());
				messages.add(message);
			}
		}

		if (!messages.isEmpty()) {
			Status status = new Status("SECURITY : unable to set feature(s)", messages);
			securityExceptionAlert.alert(status);
		}
	}
	
	/**
	 * Sets the feature to the factory
	 * 
	 * @param factory to set the feature to
	 * @param feature {@link String} feature constraint to set
	 * @param value {@link Boolean} value of the feature to add
	 * @throws Exception in case if any exception occurs
	 */
	protected abstract void setSecurityFeature(F factory, String feature, Boolean value) throws Exception;

	/**
	 * Sets all attributes to the factory
	 *
	 * @param factory object
	 */
	protected void setSecurityAttributes(F factory) {
		List<String> messages = new ArrayList<>();
		for (Map.Entry<String, Object> entry : attributes.entrySet()) {
			try {
				setSecurityAttribute(factory, entry.getKey(), entry.getValue());
			} catch (Exception e) {
				String message = String.format(
						"Attribute '%s' = '%s'. Cause : %s",
						entry.getKey(), entry.getValue(), e.getMessage());
				messages.add(message);
			}
		}

		if (!messages.isEmpty()) {
			Status status = new Status("SECURITY : unable to set attribute(s)", messages);
			securityExceptionAlert.alert(status);
		}
	}
	
	/**
	 * Sets the attribute to the factory
	 * 
	 * @param factory {@code Factory} to set the attribute to
	 * @param attribute {@link String} attribute constraint to set
	 * @param value {@link Object} value of the attribute to add
	 * @throws Exception in case if any exception occurs
	 */
	protected abstract void setSecurityAttribute(F factory, String attribute, Object value) throws Exception;

}
