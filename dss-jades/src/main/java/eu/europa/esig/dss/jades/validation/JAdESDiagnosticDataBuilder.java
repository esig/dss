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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentDiagnosticDataBuilder;

/**
 * DiagnosticDataBuilder for a JWS signature
 *
 */
public class JAdESDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

    /**
     * Default constructor
     */
    public JAdESDiagnosticDataBuilder() {
        // empty
    }

    @Override
    public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
        XmlSignature xmlSignature = super.buildDetachedXmlSignature(signature);
        JAdESSignature jadesSignature = (JAdESSignature) signature;
        xmlSignature.setSignatureType(jadesSignature.getSignatureType());
        return xmlSignature;
    }

}
