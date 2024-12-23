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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class XmlNonAdESExtensionTToLTAWithExpiredUserTest extends AbstractXAdESTestExtension {

    private static final DSSNamespace xmldsigNamespace = XMLDSigNamespace.NS;

    private CertificateVerifier certificateVerifier;
    private XAdESService service;

    @BeforeEach
    void init() throws Exception {
        certificateVerifier = getCompleteCertificateVerifier();
        service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        return certificateVerifier;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(getSigningCert().getNotAfter());
        calendar.add(Calendar.MONTH, -6);
        Date tstTime = calendar.getTime();
        return getGoodTsaByTime(tstTime);
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
        return signatureParameters;
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        DSSDocument signedDocument = super.getSignedDocument(doc);
        Document docDom = DomUtils.buildDOM(signedDocument);
        NodeList signatures = DomUtils.getNodeList(docDom, XMLDSigPath.ALL_SIGNATURES_PATH);
        assertEquals(1, signatures.getLength());
        Node signatureElement = signatures.item(0);
        Node signatureValueNode = DomUtils.getElement(signatureElement, XMLDSigPath.SIGNATURE_VALUE_PATH);
        final Element keyInfoDom = DomUtils.createElementNS(docDom, xmldsigNamespace, XMLDSigElement.KEY_INFO);
        signatureValueNode.getParentNode().insertBefore(keyInfoDom, signatureValueNode.getNextSibling());
        for (CertificateToken token : getCertificateChain()) {
            // <ds:X509Data>
            final Element x509DataDom = DomUtils.createElementNS(docDom, xmldsigNamespace, XMLDSigElement.X509_DATA);
            keyInfoDom.appendChild(x509DataDom);
            DomUtils.addTextElement(docDom, x509DataDom, xmldsigNamespace, XMLDSigElement.X509_SUBJECT_NAME, token.getSubject().getRFC2253());
            DomUtils.addTextElement(docDom, x509DataDom, xmldsigNamespace, XMLDSigElement.X509_CERTIFICATE, Utils.toBase64(token.getEncoded()));
        }
        return DomUtils.createDssDocumentFromDomDocument(docDom, signedDocument.getName());
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
        assertFalse(signature.isSigningCertificateReferencePresent());
        assertFalse(signature.isSigningCertificateReferenceUnique());
        assertNotNull(signature.getSigningCertificate());
        assertEquals(3, signature.getCertificateChain().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected XAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected String getSigningAlias() {
        return EXPIRED_USER;
    }

}
