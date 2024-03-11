package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class XAdESLevelBMultipleSameContentTstsTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private DSSDocument documentToSign;

    private Date signingDate;
    private TimestampToken contentTimestamp;

    @BeforeEach
    public void init() throws Exception {
        service = new XAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signingDate = new Date();
        contentTimestamp = service.getContentTimestamp(documentToSign, getSignatureParameters());

        DomUtils.registerNamespace(new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades"));
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        // Stateless mode
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        if (contentTimestamp != null) {
            signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp, contentTimestamp));
        }
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument firstSigned = super.sign();

        contentTimestamp = service.getContentTimestamp(documentToSign, getSignatureParameters());
        DSSDocument secondSigned = super.sign();
        compareContentTimestampIdentifiers(firstSigned, secondSigned);

        return secondSigned;
    }

    private void compareContentTimestampIdentifiers(DSSDocument firstSigned, DSSDocument secondSigned) {
        List<String> firstContentTstIds = getContentTstIds(firstSigned);
        assertEquals(2, firstContentTstIds.size());
        assertNotEquals(firstContentTstIds.get(0), firstContentTstIds.get(1));
        List<String> secondContentTstIds = getContentTstIds(secondSigned);
        assertEquals(2, secondContentTstIds.size());
        assertNotEquals(secondContentTstIds.get(0), secondContentTstIds.get(1));
        assertFalse(Utils.containsAny(firstContentTstIds, secondContentTstIds));
        assertFalse(Utils.containsAny(secondContentTstIds, firstContentTstIds));
    }

    private List<String> getContentTstIds(DSSDocument document) {
        Document dom = DomUtils.buildDOM(document);
        NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(dom);
        assertEquals(1, signaturesList.getLength());

        Node signature = signaturesList.item(0);

        String xpath = "./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties/xades:AllDataObjectsTimeStamp";
        NodeList contentTstList = DomUtils.getNodeList(signature, xpath);
        assertEquals(2, contentTstList.getLength());

        List<String> result = new ArrayList<>();
        for (int i = 0; i < contentTstList.getLength(); i++) {
            Element contentTstNode = (Element) contentTstList.item(i);
            String id = contentTstNode.getAttribute("Id");
            result.add(id);
        }
        return result;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
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
