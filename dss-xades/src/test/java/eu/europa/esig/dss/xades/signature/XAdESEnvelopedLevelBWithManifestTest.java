package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESEnvelopedLevelBWithManifestTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private DSSDocument manifest;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument("src/test/resources/sample.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);

        DSSReference envelopedManifestReference = new DSSReference();
        envelopedManifestReference.setId("r-enveloped");
        envelopedManifestReference.setUri("");
        envelopedManifestReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        envelopedManifestReference.setContents(documentToSign);
        envelopedManifestReference.setTransforms(Arrays.asList(new EnvelopedSignatureTransform(),
                new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        ManifestBuilder manifestBuilder = new ManifestBuilder("manifest", Arrays.asList(envelopedManifestReference));
        manifest = manifestBuilder.build();

        DSSReference manifestReference = new DSSReference();
        manifestReference.setId("r-manifest");
        manifestReference.setType("http://www.w3.org/2000/09/xmldsig#Manifest");
        manifestReference.setUri("#manifest");
        manifestReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA512);
        manifestReference.setContents(manifest);
        manifestReference.setTransforms(Arrays.asList(new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));

        signatureParameters.setReferences(Arrays.asList(manifestReference));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();
        Document documentDom = DomUtils.buildDOM(signedDocument);
        NodeList signatures = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDom.getDocumentElement());
        Element signatureElement = (Element) signatures.item(0);

        final Element objectDom = DomUtils.createElementNS(documentDom, XAdESNamespaces.XMLDSIG, XMLDSigElement.OBJECT);
        signatureElement.appendChild(objectDom);

        Document manifestDocument = DomUtils.buildDOM(manifest);
        Node manifestNode = manifestDocument.getDocumentElement();

        manifestNode = documentDom.importNode(manifestNode, true);
        objectDom.appendChild(manifestNode);

        documentToSign = manifest; // in order to verify extracted original documents correctly

        return new InMemoryDocument(DSSXMLUtils.serializeNode(documentDom), signedDocument.getName());
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        assertEquals(3, digestMatchers.size());

        int manifestCounter = 0;
        int manifestEntryCounter = 0;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
            if (DigestMatcherType.MANIFEST.equals(digestMatcher.getType())) {
                ++manifestCounter;
            } else if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
                ++manifestEntryCounter;
            }
        }
        assertEquals(1, manifestCounter);
        assertEquals(1, manifestEntryCounter);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(2, signatureScopes.size());

        boolean manifestRefFound = false;
        boolean envelopedRefFound = false;
        for (XmlSignatureScope signatureScope : signatureScopes) {
            assertNotNull(signatureScope.getSignerData());
            assertEquals(SignatureScopeType.FULL, signatureScope.getScope());
            assertNotNull(signatureScope.getDescription());
            if ("r-manifest".equals(signatureScope.getName())) {
                assertEquals(1, signatureScope.getTransformations().size());
                manifestRefFound = true;
            } else if ("r-enveloped".equals(signatureScope.getName())) {
                assertEquals(2, signatureScope.getTransformations().size());
                envelopedRefFound = true;
            }
        }
        assertTrue(manifestRefFound);
        assertTrue(envelopedRefFound);
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
