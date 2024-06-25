package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;

public class XAdESXPathPlacementWithEmptyNamespaceTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample-oasis.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        DSSNamespace xmldsigNamespace = new DSSNamespace(XMLDSigNamespace.NS.getUri(), "");
        signatureParameters.setXmldsigNamespace(xmldsigNamespace);

        signatureParameters.setXPathElementPlacement(XAdESSignatureParameters.XPathElementPlacement.XPathAfter);
        signatureParameters.setXPathLocationString("//*[local-name()='GuaranteeCertificate']//*[local-name()='UBLExtensions']//*[local-name()" +
                "='UBLExtension']//*[local-name()='ExtensionContent']");

        service = new XAdESService(getCompleteCertificateVerifier());
    }

    @Override
    protected String getCanonicalizationMethod() {
        return CanonicalizationMethod.EXCLUSIVE; // used by default
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
