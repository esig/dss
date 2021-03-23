package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import eu.europa.esig.dss.xades.reference.XPathEnvelopedSignatureTransform;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XAdESLevelBEnvelopedWithXPointerTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        List<DSSReference> dssReferences = new ArrayList<>();
        DSSReference reference = new DSSReference();
        reference.setContents(documentToSign);
        reference.setId("REF-ID1");
        reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        reference.setUri("#xpointer(/)");
        List<DSSTransform> transforms = new ArrayList<>();
        DSSTransform transform = new XPath2FilterTransform("/*/ds:Signature", "subtract");
        transforms.add(transform);
        reference.setTransforms(transforms);
        dssReferences.add(reference);

        signatureParameters.setReferences(dssReferences);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(1, signatureScopes.size());

        XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
        assertNotNull(xmlSignatureScope.getSignerData());
        assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
        assertEquals("XPointer query to root XML element with transformations.", xmlSignatureScope.getDescription());

        List<String> transformations = xmlSignatureScope.getTransformations();
        assertEquals(1, transformations.size());

        String transform = transformations.get(0);
        assertEquals("XPath Filter 2.0 Transform (Filter: subtract; XPath: /*/ds:Signature)", transform);
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
