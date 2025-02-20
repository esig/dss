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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESDoubleSignatureNotParallelDiffLocationInvalidWithEnvelopedTransformTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private DSSDocument originalDocument;

    @BeforeEach
    void init() throws Exception {
        originalDocument = new FileDocument(new File("src/test/resources/sample-with-different-id.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        signatureParameters = initSignatureParameters("hello", "world");
        DSSDocument signed = super.sign();

        awaitOneSecond();

        documentToSign = signed;
        signatureParameters = initSignatureParameters("world", "hello");

        DSSDocument doubleSigned = super.sign();

        documentToSign = originalDocument;
        return doubleSigned;
    }

    private XAdESSignatureParameters initSignatureParameters(String signedNodeId, String locationNodeId) {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        signatureParameters.setXPathLocationString(String.format("//*[@Id='%s']", locationNodeId));

        final List<DSSReference> references = new ArrayList<>();

        DSSReference dssReference = new DSSReference();
        dssReference.setUri(String.format("#%s", signedNodeId));
        dssReference.setContents(documentToSign);
        dssReference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

        final List<DSSTransform> transforms = new ArrayList<>();

        EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
        transforms.add(signatureTransform);

        CanonicalizationTransform dssTransform = new CanonicalizationTransform(getCanonicalizationMethod());
        transforms.add(dssTransform);

        dssReference.setTransforms(transforms);
        references.add(dssReference);

        signatureParameters.setReferences(references);
        return signatureParameters;
    }

    @Override
    @Test
    public void signAndVerify() {
        Exception exception = assertThrows(IllegalInputException.class, () -> sign());
        assertEquals(
                "The parallel signature is not possible! The provided file contains a signature "
                        + "with an 'http://www.w3.org/2000/09/xmldsig#enveloped-signature' transform.",
                exception.getMessage());
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
