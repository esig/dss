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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.AbstractXAdESTestSignature;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2589WithTLevelExtensionTest extends AbstractXAdESTestSignature {

    private final static DSSDocument ORIGINAL_DOC = new FileDocument("src/test/resources/sample.xml");

    private XAdESService service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = ORIGINAL_DOC;
        signatureParameters = initSignatureParameters();
        service = new XAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    private XAdESSignatureParameters initSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        Document newDom = DomUtils.buildDOM();
        Element wrapper = newDom.createElement("Wrapper");
        newDom.appendChild(wrapper);

        DSSDocument signedXML = super.sign();
        Document signedDocDom = DomUtils.buildDOM(signedXML);

        Node signatureNode = signedDocDom.getFirstChild();
        signatureNode = newDom.importNode(signatureNode, true);
        wrapper.appendChild(signatureNode);

        DSSDocument wrappedSignatureDoc = new InMemoryDocument(DSSXMLUtils.serializeNode(newDom));
        documentToSign = wrappedSignatureDoc;

        signatureParameters = initSignatureParameters();
        signatureParameters.setEmbedXML(true);

        DSSDocument signedDocument = super.sign();

        XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
        return service.extendDocument(signedDocument, extensionParameters);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean bLevelSigFound = false;
        boolean tLevelSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            if (SignatureLevel.XAdES_BASELINE_B.equals(diagnosticData.getSignatureFormat(sigId))) {
                bLevelSigFound = true;
            } else if (SignatureLevel.XAdES_BASELINE_T.equals(diagnosticData.getSignatureFormat(sigId))) {
                tLevelSigFound = true;
            }
        }
        assertTrue(bLevelSigFound);
        assertTrue(tLevelSigFound);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        boolean originalDocSigFound = false;
        boolean sigDocSigFound = false;
        for (String sigId : diagnosticData.getSignatureIdList()) {
            List<DSSDocument> originalDocuments = validator.getOriginalDocuments(sigId);
            assertEquals(1, originalDocuments.size());
            if (SignatureLevel.XAdES_BASELINE_B.equals(diagnosticData.getSignatureFormat(sigId)) &&
                    Arrays.equals(DSSXMLUtils.canonicalize(CanonicalizationMethod.EXCLUSIVE, DSSUtils.toByteArray(ORIGINAL_DOC)),
                    DSSXMLUtils.canonicalize(CanonicalizationMethod.EXCLUSIVE, DSSUtils.toByteArray(originalDocuments.get(0))))) {
                originalDocSigFound = true;
            } else if (SignatureLevel.XAdES_BASELINE_T.equals(diagnosticData.getSignatureFormat(sigId)) &&
                    Arrays.equals(DSSXMLUtils.canonicalize(CanonicalizationMethod.EXCLUSIVE, DSSUtils.toByteArray(documentToSign)),
                    DSSXMLUtils.canonicalize(CanonicalizationMethod.EXCLUSIVE, DSSUtils.toByteArray(originalDocuments.get(0))))) {
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
    protected XAdESService getService() {
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
