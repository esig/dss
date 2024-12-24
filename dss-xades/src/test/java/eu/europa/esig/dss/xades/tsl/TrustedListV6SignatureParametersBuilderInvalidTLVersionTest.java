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
package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.AbstractXAdESTestSignature;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TrustedListV6SignatureParametersBuilderInvalidTLVersionTest extends AbstractXAdESTestSignature {

    private static final String REFERENCE_ID = "dss-tl-id-1";
    private static final DigestAlgorithm REFERENCE_DIGEST_ALGORITHM = DigestAlgorithm.SHA512;

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Test
    @Override
    public void signAndVerify() {
        TrustedListV6SignatureParametersBuilder signatureParametersBuilder = getSignatureParametersBuilder();
        Exception exception = assertThrows(IllegalInputException.class, signatureParametersBuilder::assertConfigurationIsValid);
        assertEquals("XML Trusted List failed the validation : TSL Version '5' found in the XML Trusted List " +
                "does not correspond to the target version defined by the builder '6'! " +
                "Please modify the document or change to the appropriate builder.", exception.getMessage());
    }

    protected TrustedListV6SignatureParametersBuilder getSignatureParametersBuilder() {
        return new TrustedListV6SignatureParametersBuilder(getSigningCert(), documentToSign)
                .setReferenceId(REFERENCE_ID)
                .setReferenceDigestAlgorithm(REFERENCE_DIGEST_ALGORITHM);
    }

    @Override
    protected String getCanonicalizationMethod() {
        return CanonicalizationMethod.EXCLUSIVE;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}
