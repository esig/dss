package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESManifestLevelBPartialValidationWrongFilenameTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {

        List<DSSDocument> documents = new ArrayList<>();
        documents.add(new FileDocument("src/test/resources/sample.png"));
        documents.add(new FileDocument("src/test/resources/sample.txt"));
        documents.add(new FileDocument("src/test/resources/sample.xml"));
        ManifestBuilder builder = new ManifestBuilder(DigestAlgorithm.SHA512, documents);

        documentToSign = builder.build();

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureParameters.setManifestSignature(true);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        List<DSSDocument> documents = new ArrayList<>();
        DSSDocument documentOne = new FileDocument("src/test/resources/sample.png");
        documentOne.setName("sample.xml");
        documents.add(documentOne);
        validator.setDetachedContents(documents);
        return validator;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signatureWrapper.isSignatureIntact());
        assertTrue(signatureWrapper.isSignatureValid());
        assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));

        int nbFoundManifestEntries = 0;
        int nbInvalidManifestEntries = 0;
        int nbNotFoundManifestEntries = 0;
        boolean foundManifest = false;
        boolean foundSignedProperties = false;
        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            switch (xmlDigestMatcher.getType()) {
                case MANIFEST:
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    foundManifest = true;
                    break;
                case MANIFEST_ENTRY:
                    if (xmlDigestMatcher.isDataFound()) {
                        if (xmlDigestMatcher.isDataIntact()) {
                            assertNotNull(xmlDigestMatcher.getDocumentName());
                            assertNotEquals(xmlDigestMatcher.getUri(), xmlDigestMatcher.getDocumentName());
                            nbFoundManifestEntries++;
                        } else {
                            assertNotNull(xmlDigestMatcher.getDocumentName());
                            assertEquals(xmlDigestMatcher.getUri(), xmlDigestMatcher.getDocumentName());
                            nbInvalidManifestEntries++;
                        }
                    } else {
                        assertFalse(xmlDigestMatcher.isDataIntact());
                        nbNotFoundManifestEntries++;
                    }
                    break;
                case SIGNED_PROPERTIES:
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    foundSignedProperties = true;
                    break;
                default:
                    break;
            }
        }

        assertTrue(foundManifest);
        assertEquals(1, nbFoundManifestEntries);
        assertEquals(1, nbInvalidManifestEntries);
        assertEquals(1, nbNotFoundManifestEntries);
        assertTrue(foundSignedProperties);
    }


    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        super.validateETSISignersDocument(signersDocument);

        DigestAlgAndValueType digestAlgoAndValue = getDigestAlgoAndValue(signersDocument);
        assertNotNull(digestAlgoAndValue);
        assertNotNull(digestAlgoAndValue.getDigestMethod());
        assertNotNull(digestAlgoAndValue.getDigestValue());

        List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
        assertEquals(3, validationObjects.size());
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
