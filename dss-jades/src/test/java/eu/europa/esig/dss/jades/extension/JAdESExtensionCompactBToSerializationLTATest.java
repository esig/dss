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
package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class JAdESExtensionCompactBToSerializationLTATest extends AbstractJAdESTestExtension {

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        return signatureParameters;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_B;
    }

    @Override
    protected JAdESSignatureParameters getExtensionParameters() {
        JAdESSignatureParameters signatureParameters = super.getExtensionParameters();
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        return signatureParameters;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LTA;
    }

    @Override
    protected void onDocumentSigned(DSSDocument signedDocument) {
        super.onDocumentSigned(signedDocument);

        JWSCompactSerializationParser parser = new JWSCompactSerializationParser(signedDocument);
        JWS jws = parser.parse();
        assertNotNull(jws);
    }

    @Override
    protected void onDocumentExtended(DSSDocument extendedDocument) {
        super.onDocumentExtended(extendedDocument);

        JWSJsonSerializationParser parser = new JWSJsonSerializationParser(extendedDocument);
        JWSJsonSerializationObject jsonSerializationObject = parser.parse();
        assertNotNull(jsonSerializationObject);
        assertEquals(JWSSerializationType.JSON_SERIALIZATION,  jsonSerializationObject.getJWSSerializationType());
    }

}
