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

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;
import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESLevelBInternallyDetachedWithInvalidXPathPlacementTest extends AbstractXAdESTestSignature {

    private static final DSSDocument DOC = new FileDocument(new File("src/test/resources/sample-with-id.xml"));

    private static final String CONTAINER_NODE_NAME = "signature-container";

    private static final String XPATH = "//*[local-name() = 'ElementNotExists']";

    private XAdESService service;
    private DSSDocument documentToSign;
    private XAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        documentToSign = DOC;
        service = new XAdESService(getOfflineCertificateVerifier());
        signatureParameters = initSignatureParameters();
    }

    private XAdESSignatureParameters initSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.INTERNALLY_DETACHED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        signatureParameters = initSignatureParameters();

        Document rootDocument = DomUtils.buildDOM();
        Element rootElement = rootDocument.createElement(CONTAINER_NODE_NAME);
        rootDocument.appendChild(rootElement);
        signatureParameters.setRootDocument(rootDocument);

        DSSDocument signedDocument = super.sign();

        awaitOneSecond();

        documentToSign = signedDocument;
        signatureParameters = initSignatureParameters();
        signatureParameters.setXPathLocationString(XPATH);

        DSSReference dssReference = new DSSReference();
        dssReference.setId("r-" + signatureParameters.getDeterministicId());
        dssReference.setUri("#ROOT");
        dssReference.setTransforms(Arrays.asList(new CanonicalizationTransform(CanonicalizationMethod.INCLUSIVE)));
        dssReference.setContents(documentToSign);
        dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        signatureParameters.setReferences(Arrays.asList(dssReference));

        DSSDocument doubleSignedDoc = super.sign();
        documentToSign = DOC;
        return doubleSignedDoc;
    }

    @Test
    @Override
    public void signAndVerify() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::signAndVerify);
        assertEquals(String.format("Unable to find an element corresponding to XPath location '%s'", XPATH), exception.getMessage());
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
