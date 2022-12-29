package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class XmlNotAdESExtensionTToLTARevokedUserTest extends AbstractXAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_T;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        return signatureParameters;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(getSigningCert().getNotBefore());
        calendar.add(Calendar.MONTH, 6);
        return getGoodTsaByTime(calendar.getTime());
    }

    @Override
    protected DSSDocument getSignedDocument(DSSDocument doc) {
        DSSDocument signedDocument = super.getSignedDocument(doc);
        Document docDom = DomUtils.buildDOM(signedDocument);
        NodeList signatures = DomUtils.getNodeList(docDom, XMLDSigPaths.ALL_SIGNATURES_PATH);
        assertEquals(1, signatures.getLength());
        Node signatureElement = signatures.item(0);
        Node signatureValueNode = DomUtils.getElement(signatureElement, XMLDSigPaths.SIGNATURE_VALUE_PATH);
        final Element keyInfoDom = DomUtils.createElementNS(docDom, XAdESNamespaces.XMLDSIG, XMLDSigElement.KEY_INFO);
        signatureValueNode.getParentNode().insertBefore(keyInfoDom, signatureValueNode.getNextSibling());
        for (CertificateToken token : getCertificateChain()) {
            // <ds:X509Data>
            final Element x509DataDom = DomUtils.createElementNS(docDom, XAdESNamespaces.XMLDSIG, XMLDSigElement.X509_DATA);
            keyInfoDom.appendChild(x509DataDom);
            DomUtils.addTextElement(docDom, x509DataDom, XAdESNamespaces.XMLDSIG, XMLDSigElement.X509_SUBJECT_NAME, token.getSubject().getRFC2253());
            DomUtils.addTextElement(docDom, x509DataDom, XAdESNamespaces.XMLDSIG, XMLDSigElement.X509_CERTIFICATE, Utils.toBase64(token.getEncoded()));
        }
        return DomUtils.createDssDocumentFromDomDocument(docDom, signedDocument.getName());
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_LTA;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        assertFalse(signatureWrapper.isSigningCertificateIdentified());
        assertFalse(signatureWrapper.isSigningCertificateReferencePresent());
        assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());

        CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
        assertNull(signingCertificateReference);

        CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkOriginalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getFirstSignatureFormat());

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<TimestampWrapper> timestampList = signature.getTimestampList();
        assertEquals(1, timestampList.size());
        assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getFirstSignatureFormat());

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<TimestampWrapper> timestampList = signature.getTimestampList();
        assertEquals(2, timestampList.size());
        assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampList.get(0).getType());
        assertEquals(TimestampType.ARCHIVE_TIMESTAMP, timestampList.get(1).getType());
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}
