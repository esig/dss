package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESEnvelopingWithCustomObjectsTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        DSSObject xmlObject = new DSSObject();
        xmlObject.setContent(new FileDocument("src/test/resources/ns-prefixes-sample.xml"));
        xmlObject.setId("o-id-xml");

        DSSObject base64Object = new DSSObject();
        DSSDocument image = new FileDocument("src/test/resources/sample.png");
        String base64EncodedImage = Utils.toBase64(DSSUtils.toByteArray(image));
        base64Object.setContent(new InMemoryDocument(base64EncodedImage.getBytes()));
        base64Object.setId("o-id-image");
        base64Object.setMimeType(MimeType.PNG);
        base64Object.setEncodingAlgorithm("http://www.w3.org/2000/09/xmldsig#base64");

        signatureParameters.setObjects(Arrays.asList(xmlObject, base64Object));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        Document document = DomUtils.buildDOM(byteArray);
        NodeList objectList = DomUtils.getNodeList(document.getDocumentElement(), XMLDSigPaths.OBJECT_PATH);
        assertEquals(4, objectList.getLength());

        boolean xmlObjectFound = false;
        boolean base64ObjectFound = false;
        for (int ii = 0; ii < objectList.getLength(); ii++) {
            Node objectNode = objectList.item(ii);
            String id = DSSXMLUtils.getAttribute(objectNode, XMLDSigAttribute.ID.getAttributeName());
            if ("o-id-xml".equals(id)) {
                Node content = objectNode.getFirstChild();
                assertEquals(Node.ELEMENT_NODE, content.getNodeType());

                xmlObjectFound = true;

            } else if ("o-id-image".equals(id)) {
                Node content = objectNode.getFirstChild();
                assertEquals(Node.TEXT_NODE, content.getNodeType());

                String textContent = content.getTextContent();
                assertTrue(Utils.isBase64Encoded(textContent));

                assertEquals(MimeType.PNG.getMimeTypeString(),
                        DSSXMLUtils.getAttribute(objectNode, XMLDSigAttribute.MIME_TYPE.getAttributeName()));
                assertEquals("http://www.w3.org/2000/09/xmldsig#base64",
                        DSSXMLUtils.getAttribute(objectNode, XMLDSigAttribute.ENCODING.getAttributeName()));

                base64ObjectFound = true;
            }
        }
        assertTrue(xmlObjectFound);
        assertTrue(base64ObjectFound);
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

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
