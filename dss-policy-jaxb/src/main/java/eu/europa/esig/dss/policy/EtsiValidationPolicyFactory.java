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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Loads a DSS XML Validation Policy based on the ETSI TS 102 853 standard.
 *
 */
public class EtsiValidationPolicyFactory implements ValidationPolicyFactory {

    /** The default validation policy path */
    private static final String DEFAULT_VALIDATION_POLICY_LOCATION = "/policy/constraint.xml";

    /**
     * Default constructor
     */
    public EtsiValidationPolicyFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument validationPolicyDocument) {
        try (InputStream is = validationPolicyDocument.openStream()) {
            ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(is, false);
            return constraintsParameters != null;
        } catch (IOException | JAXBException | XMLStreamException | SAXException e) {
            return false;
        }
    }

    @Override
    public ValidationPolicy loadDefaultValidationPolicy() {
        try {
            return loadValidationPolicy(EtsiValidationPolicyFactory.class.getResourceAsStream(DEFAULT_VALIDATION_POLICY_LOCATION));
        } catch (Exception e) {
            throw new UnsupportedOperationException(
                    String.format("Unable to load the default policy document. Reason : %s", e.getMessage()), e);
        }
    }

    @Override
    public ValidationPolicy loadValidationPolicy(DSSDocument validationPolicyDocument) {
        return loadValidationPolicy(validationPolicyDocument.openStream());
    }

    @Override
    public ValidationPolicy loadValidationPolicy(InputStream validationPolicyInputStream) {
        try (InputStream is = validationPolicyInputStream) {
            return ValidationPolicyFacade.newFacade().getValidationPolicy(is);
        } catch (Exception e) {
            throw new UnsupportedOperationException(
                    String.format("Unable to load the default policy document. Reason : %s", e.getMessage()), e);
        }
    }

}
