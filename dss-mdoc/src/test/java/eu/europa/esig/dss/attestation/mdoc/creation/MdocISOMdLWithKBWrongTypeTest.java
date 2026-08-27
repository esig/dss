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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocISOMdLWithKBWrongTypeTest extends AbstractMdocDeviceResponseTestCreation {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    private CBAdESSignatureParameters keyBindingSignatureParameters;
    private MdocKeyBindingParameters keyBindingParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setGivenName("John");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        keyBindingSignatureParameters = new CBAdESSignatureParameters();
        keyBindingSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        keyBindingSignatureParameters.setSigningCertificate(getSigningCert());

        // TODO : introduce a method that allows validation of the keyBinding signature parameters
        keyBindingParameters = new MdocKeyBindingParameters();
        keyBindingParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE); // leads to a different payload on validation
        keyBindingParameters.setSessionTranscript(buildSessionTranscript());
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean attestationSigFound = false;
        boolean kbSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertEquals(1, digestMatchers.size());
            assertEquals(DigestMatcherType.COSE_SIG_STRUCTURE, digestMatchers.get(0).getType());

            if (signatureWrapper.isKeyBindingSignature()) {
                assertTrue(digestMatchers.get(0).isDataFound());
                assertFalse(digestMatchers.get(0).isDataIntact());
                assertFalse(signatureWrapper.isBLevelTechnicallyValid());
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                kbSigFound = true;

            } else {
                assertTrue(digestMatchers.get(0).isDataFound());
                assertTrue(digestMatchers.get(0).isDataIntact());
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                attestationSigFound = true;
            }
        }
        assertTrue(attestationSigFound);
        assertTrue(kbSigFound);
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

    @Override
    protected MdocPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return keyBindingSignatureParameters;
    }

    @Override
    protected MdocKeyBindingParameters getKeyBindingParameters() {
        return keyBindingParameters;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
