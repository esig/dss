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
package eu.europa.esig.dss.xml.common;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.status.ObjectStatus;
import eu.europa.esig.dss.xml.common.exception.SecurityConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract class containing util classes helping to configure a Factory or a Validator
 *
 * @param <F> class of the object to be configured
 */
public abstract class AbstractConfigurator<F> {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractConfigurator.class);

    /** Map of features to set */
    private final Map<String, Boolean> features = new HashMap<>();

    /** Map of attribute names and values to set */
    private final Map<String, Object> attributes = new HashMap<>();

    /** Defines the behaviour for processing a security exception */
    private StatusAlert securityExceptionAlert = new ExceptionOnStatusAlert();

    /**
     * Default constructor initializing empty maps of security features and attributes
     */
    protected AbstractConfigurator() {
        // empty
    }

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
    public AbstractConfigurator<F> enableFeature(String feature) {
        return setFeature(feature, true);
    }

    /**
     * Disables a custom feature
     *
     * @param feature {@link String} the feature constraint
     * @return this builder
     */
    public AbstractConfigurator<F> disableFeature(String feature) {
        return setFeature(feature, false);
    }

    private AbstractConfigurator<F> setFeature(String feature, boolean value) {
        Objects.requireNonNull(feature, "The feature constraint cannot be null!");
        Boolean currentValue = features.get(feature);
        if (currentValue != null && currentValue != value) {
            LOG.warn("SECURITY : feature with the name [{}] changed from [{}] to [{}]", feature, currentValue, value);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("The feature {} = {} has been added to the configuration", feature, value);
        }
        features.put(feature, value);
        return this;
    }

    /**
     * Sets a custom attribute.
     *
     * @param attribute {@link String} attribute constraint to set
     * @param value {@link Object} a value to define for the attribute
     * @return this builder
     */
    public AbstractConfigurator<F> setAttribute(String attribute, Object value) {
        Objects.requireNonNull(attribute, "The attribute constraint cannot be null!");
        Object currentValue = attributes.get(attribute);
        if (currentValue != null && currentValue.equals(value)) {
            LOG.warn("SECURITY : attribute with the name [{}] changed from [{}] to [{}]", attribute, currentValue, value);
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
    public AbstractConfigurator<F> removeAttribute(String attribute) {
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
        ObjectStatus status = new ObjectStatus();
        for (Map.Entry<String, Boolean> entry : features.entrySet()) {
            try {
                setSecurityFeature(factory, entry.getKey(), entry.getValue());
            } catch (SecurityConfigurationException e) {
                status.addRelatedObjectIdentifierAndErrorMessage(entry.getKey(), e.getMessage());
            }
        }

        if (!status.isEmpty()) {
            status.setMessage("SECURITY : unable to set feature(s)!");
            securityExceptionAlert.alert(status);
        }
    }

    /**
     * Sets the feature to the factory
     *
     * @param factory to set the feature to
     * @param feature {@link String} feature constraint to set
     * @param value {@link Boolean} value of the feature to add
     * @throws SecurityConfigurationException in case if any exception occurs
     */
    protected abstract void setSecurityFeature(F factory, String feature, Boolean value) throws SecurityConfigurationException;

    /**
     * Sets all attributes to the factory
     *
     * @param factory object
     */
    protected void setSecurityAttributes(F factory) {
        ObjectStatus status = new ObjectStatus();
        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            try {
                setSecurityAttribute(factory, entry.getKey(), entry.getValue());
            } catch (SecurityConfigurationException e) {
                status.addRelatedObjectIdentifierAndErrorMessage(entry.getKey(), e.getMessage());
            }
        }

        if (!status.isEmpty()) {
            status.setMessage("SECURITY : unable to set attribute(s)!");
            securityExceptionAlert.alert(status);
        }
    }

    /**
     * Sets the attribute to the factory
     *
     * @param factory {@code Factory} to set the attribute to
     * @param attribute {@link String} attribute constraint to set
     * @param value {@link Object} value of the attribute to add
     * @throws SecurityConfigurationException in case if any exception occurs
     */
    protected abstract void setSecurityAttribute(F factory, String attribute, Object value) throws SecurityConfigurationException;

}