package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;
import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XAdESLevelBInternallyDetachedWithXPathLocationTest extends AbstractXAdESTestSignature {

    private static final DSSDocument DOC = new FileDocument(new File("src/test/resources/sample-with-id.xml"));

    private static final String CONTAINER_NODE_NAME = "signature-container";

    private XAdESService service;
    private DSSDocument documentToSign;
    private XAdESSignatureParameters signatureParameters;

    @BeforeEach
    public void init() {
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

        documentToSign = signedDocument;
        signatureParameters = initSignatureParameters();
        signatureParameters.setXPathLocationString("//" + CONTAINER_NODE_NAME);

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

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        Document document = DomUtils.buildDOM(byteArray);
        Element documentElement = document.getDocumentElement();
        assertEquals(CONTAINER_NODE_NAME, documentElement.getLocalName());

        NodeList childNodes = documentElement.getChildNodes();
        assertEquals(3, childNodes.getLength());

        int signingDocumentCounter = 0;
        int signatureCounter = 0;
        for (int ii = 0; ii < childNodes.getLength(); ii++) {
            Node node = childNodes.item(ii);
            assertEquals(Node.ELEMENT_NODE, node.getNodeType());
            Element element = (Element) node;
            if ("ROOT".equals(element.getAttribute("Id"))) {
                ++signingDocumentCounter;
            }
            if ("Signature".equals(element.getLocalName())) {
                ++signatureCounter;
            }
        }
        assertEquals(1, signingDocumentCounter);
        assertEquals(2, signatureCounter);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
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
