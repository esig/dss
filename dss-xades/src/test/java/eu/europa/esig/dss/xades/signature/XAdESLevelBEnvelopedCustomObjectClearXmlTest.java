package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

class XAdESLevelBEnvelopedCustomObjectClearXmlTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);

        DSSReference envelopedReference = new DSSReference();
        envelopedReference.setId("r-enveloped");
        envelopedReference.setUri("");
        envelopedReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        envelopedReference.setContents(documentToSign);
        envelopedReference.setTransforms(Arrays.asList(new EnvelopedSignatureTransform(),
                new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        DSSDocument envelopingDocToSign = new FileDocument("src/test/resources/sample-c14n.xml");
        Document originalDocDom = DomUtils.buildDOM(envelopingDocToSign);

        Document objectDom = DomUtils.buildDOM();
        Element objectElement = DomUtils.createElementNS(objectDom, XMLDSigNamespace.NS, XMLDSigElement.OBJECT);
        objectElement.setAttribute(XMLDSigAttribute.ID.getAttributeName(), "obj");
        objectDom.appendChild(objectElement);

        Node importedNode = objectDom.importNode(originalDocDom.getDocumentElement(), true);
        objectElement.appendChild(importedNode);

        DSSReference envelopingReference = new DSSReference();
        envelopingReference.setId("r-obj");
        envelopingReference.setType("http://www.w3.org/2000/09/xmldsig#Object");
        envelopingReference.setUri("#obj");
        envelopingReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        envelopingReference.setContents(DomUtils.createDssDocumentFromDomDocument(objectDom, "objectDoc"));
        envelopingReference.setTransforms(Collections.singletonList(new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        signatureParameters.setReferences(Arrays.asList(envelopedReference, envelopingReference));

        DSSObject object = new DSSObject();
        object.setId("obj");
        object.setContent(envelopingDocToSign);
        envelopingReference.setObject(object);

        service = new XAdESService(getOfflineCertificateVerifier());
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
