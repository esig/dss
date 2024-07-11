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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBCommitmentTypeQualifierTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private CommonCommitmentType commitmentTypeIndication;

    private DSSDocument xmlDocument;
    private DSSDocument base64Document;

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

        commitmentTypeIndication = new CommonCommitmentType();
        commitmentTypeIndication.setUri("http://nowina.lu/approved");
        commitmentTypeIndication.setQualifier(ObjectIdentifierQualifier.OID_AS_URI);
        commitmentTypeIndication.setDescription("Approved");
        commitmentTypeIndication.setDocumentationReferences("http://nowina.lu/approved.pdf", "https://uri.etsi.org/01903/v1.2.2/ts_101903v010202p.pdf");
        commitmentTypeIndication.setSignedDataObjects("r-" + signatureParameters.getDeterministicId() + "-1");

        xmlDocument = new FileDocument("src/test/resources/ns-prefixes-sample.xml");

        CommitmentQualifier xmlCommitmentQualifier = new CommitmentQualifier();
        xmlCommitmentQualifier.setContent(xmlDocument);

        DSSDocument image = new FileDocument("src/test/resources/sample.png");
        String base64EncodedImage = Utils.toBase64(DSSUtils.toByteArray(image));
        base64Document = new InMemoryDocument(base64EncodedImage.getBytes());

        CommitmentQualifier base64CommitmentQualifier = new CommitmentQualifier();
        base64CommitmentQualifier.setContent(base64Document);

        commitmentTypeIndication.setCommitmentTypeQualifiers(xmlCommitmentQualifier, base64CommitmentQualifier);

        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(commitmentTypeIndication));
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("When using URI as object identifier in XAdES, " +
                "a Qualifier shall not be present! See EN 319 132-1 for more details.", exception.getMessage());

        commitmentTypeIndication.setQualifier(null);
        return super.sign();
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        String xmlContent = new String(byteArray);
        assertFalse(xmlContent.contains(":Identifier Qualifier=\"OIDAsURI\""));
        assertTrue(xmlContent.contains(":Description>"));
        assertTrue(xmlContent.contains(":DocumentationReferences>"));
        assertTrue(xmlContent.contains(":DocumentationReference>"));
        assertTrue(xmlContent.contains(":ObjectReference>"));
        assertTrue(xmlContent.contains(":CommitmentTypeQualifiers>"));
        assertTrue(xmlContent.contains(":CommitmentTypeQualifier>"));
        assertTrue(xmlContent.contains(DomUtils.buildDOM(xmlDocument).getDocumentElement().getLocalName()));
        assertTrue(xmlContent.contains(new String(DSSUtils.toByteArray(base64Document))));
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
