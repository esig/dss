package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelBDetachedByUriByHashHttpParsWrongNameTest extends AbstractJAdESMultipleDocumentSignatureTest {

    private static final String DOC_ONE_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURIHash-1.html";
    private static final String DOC_TWO_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURIHash-2.html";

    private JAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns;
    private JAdESService jadesService;

    @BeforeEach
    void init() throws Exception {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURIHash-1.html");
        documentOne.setName(DOC_ONE_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURIHash-2.html");
        documentTwo.setName(DOC_TWO_NAME);
        documentToSigns = Arrays.asList(documentOne, documentTwo);

        jadesService = new JAdESService(getOfflineCertificateVerifier());

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURIHash-1.html");
        documentOne.setName(DOC_TWO_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURIHash-2.html");
        documentTwo.setName(DOC_ONE_NAME);
        return Arrays.asList(documentOne, documentTwo);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        int sigDCounter = 0;
        for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
            if (DigestMatcherType.SIG_D_ENTRY == digestMatcher.getType()) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                assertNull(digestMatcher.getId());
                assertNotNull(digestMatcher.getUri());
                assertNotNull(digestMatcher.getDocumentName());
                assertNotEquals(digestMatcher.getUri(), digestMatcher.getDocumentName());
                ++sigDCounter;
            }
        }
        assertEquals(2, sigDCounter);
    }

    @Override
    protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return jadesService;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

}
