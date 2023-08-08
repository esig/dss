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

import eu.europa.esig.dss.xml.XMLCanonicalizer;
import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2589Test extends AbstractXAdESTestSignature {

    private final static DSSDocument ORIGINAL_DOC = new FileDocument("src/test/resources/sample.xml");

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = ORIGINAL_DOC;
        signatureParameters = initSignatureParameters();
        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    private XAdESSignatureParameters initSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        Document newDom = DomUtils.buildDOM();
        Element embedded = newDom.createElement("embedded");
        newDom.appendChild(embedded);

        Element documentNode = newDom.createElement("Document");
        embedded.appendChild(documentNode);

        DSSDocument signedXML = super.sign();
        Document signedDocDom = DomUtils.buildDOM(signedXML);

        Node signatureNode = signedDocDom.getFirstChild();
        signatureNode = newDom.importNode(signatureNode, true);
        documentNode.appendChild(signatureNode);

        DSSDocument wrappedSignatureDoc = new InMemoryDocument(DomUtils.serializeNode(newDom));
        documentToSign = wrappedSignatureDoc;

        signatureParameters = initSignatureParameters();
        signatureParameters.setEmbedXML(true);

        return super.sign();
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        for (String sigId : diagnosticData.getSignatureIdList()) {
            assertEquals(SignatureLevel.XAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(sigId));
        }
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        boolean originalDocSigFound = false;
        boolean sigDocSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            List<DSSDocument> originalDocuments = validator.getOriginalDocuments(sigId);
            assertEquals(1, originalDocuments.size());
            if (Arrays.equals(XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(DSSUtils.toByteArray(ORIGINAL_DOC)),
                    XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(DSSUtils.toByteArray(originalDocuments.get(0))))) {
                originalDocSigFound = true;
            } else if (Arrays.equals(XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(DSSUtils.toByteArray(documentToSign)),
                    XMLCanonicalizer.createInstance(CanonicalizationMethod.EXCLUSIVE).canonicalize(DSSUtils.toByteArray(originalDocuments.get(0))))) {
                sigDocSigFound = true;
            }
        }
        assertTrue(originalDocSigFound);
        assertTrue(sigDocSigFound);
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
