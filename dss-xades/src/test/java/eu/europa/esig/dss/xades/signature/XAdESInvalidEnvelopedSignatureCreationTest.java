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

import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class XAdESInvalidEnvelopedSignatureCreationTest extends AbstractXAdESTestSignature {

    private static final DSSDocument ORIGINAL_DOCUMENT = new FileDocument(new File("src/test/resources/sample.xml"));

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = ORIGINAL_DOCUMENT;

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Test
    @Override
    public void signAndVerify() {
        DSSDocument signedDocument = super.sign();

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        documentToSign = signedDocument;

        Exception exception = assertThrows(IllegalInputException.class, () -> super.sign());
        assertEquals("Unable to create an enveloped signature for another XML signature document!", exception.getMessage());

        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "test.txt");

        exception = assertThrows(IllegalInputException.class, () -> super.sign());
        assertEquals("Enveloped signature cannot be created. Reason : the provided document is not XML!", exception.getMessage());

        documentToSign = signedDocument;

        DSSReference reference = new DSSReference();
        reference.setId("r-enveloped");
        reference.setUri("");
        reference.setContents(documentToSign);
        reference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

        final List<DSSTransform> dssTransformList = new ArrayList<>();
        DSSTransform xpathTransform = new XPath2FilterEnvelopedSignatureTransform(signatureParameters.getXmldsigNamespace());
        dssTransformList.add(xpathTransform);
        dssTransformList.add(new CanonicalizationTransform(signatureParameters.getXmldsigNamespace(), XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD));

        reference.setTransforms(dssTransformList);
        signatureParameters.setReferences(Arrays.asList(reference));

        exception = assertThrows(IllegalInputException.class, () -> super.sign());
        assertEquals(String.format("Unable to perform the next transform. The %s produced an empty output!", xpathTransform), exception.getMessage());
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
