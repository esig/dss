package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBEnvelopedWithStylesheetTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample-xml-stylesheet-with-id.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void checkDataObjectFormat(Document documentDOM) {
        super.checkDataObjectFormat(documentDOM);

        NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDOM);
        assertEquals(1, signatureNodeList.getLength());

        Element signatureElement = (Element) signatureNodeList.item(0);
        NodeList dataObjectFormatList = DomUtils.getNodeList(signatureElement, new XAdES132Paths().getDataObjectFormat());
        assertEquals(1, dataObjectFormatList.getLength());

        Element dataObjectFormat = (Element) dataObjectFormatList.item(0);
        String objectReference = dataObjectFormat.getAttribute(XAdES132Attribute.OBJECT_REFERENCE.getAttributeName());
        assertNotNull(objectReference);

        Element elementById = DomUtils.getElementById(signatureElement, DomUtils.getId(objectReference));
        assertNotNull(elementById);
        assertTrue(XMLDSigElement.REFERENCE.isSameTagName(elementById.getLocalName()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        Document originalDocument = DomUtils.buildDOM(documentToSign);

        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        assertEquals(1, originalDocuments.size());
        Document signedElement = DomUtils.buildDOM(originalDocuments.get(0));

        assertArrayEquals(DSSXMLUtils.canonicalizeSubtree(CanonicalizationMethod.EXCLUSIVE, originalDocument),
                DSSXMLUtils.canonicalizeSubtree(CanonicalizationMethod.EXCLUSIVE, signedElement));
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