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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBWithCommonCommitmentTypeOidAsUrnTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private CommonCommitmentType commitmentType;

    @BeforeEach
    void init() throws Exception {
        service = new XAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        commitmentType = new CommonCommitmentType();
        commitmentType.setOid("urn:oid:1.2.3.4.5");
        commitmentType.setDescription("Approved");
        commitmentType.setDocumentationReferences("http://nowina.lu/approved.pdf", 
                "https://uri.etsi.org/01903/v1.2.2/ts_101903v010202p.pdf");

        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(commitmentType));
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("When using OID as object identifier in XAdES, " +
                "a Qualifier shall be provided! See EN 319 132-1 for more details.", exception.getMessage());

        commitmentType.setQualifier(ObjectIdentifierQualifier.OID_AS_URI);
        exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("Qualifier 'OID_AS_URI' shall not be used for URN encoded OID! " +
                "See EN 319 132-1 for more details.", exception.getMessage());

        commitmentType.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
        return super.sign();
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);
        String xmlContent = new String(byteArray);
        assertTrue(xmlContent.contains("urn:oid:1.2.3.4.5"));
        assertTrue(xmlContent.contains(":Description>"));
        assertTrue(xmlContent.contains(":DocumentationReferences>"));
        assertTrue(xmlContent.contains(":DocumentationReference>"));
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
