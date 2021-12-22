package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESLevelBDetachedByUryWithHttpParsTest extends AbstractJAdESMultipleDocumentSignatureTest {

    private static final String DOC_ONE_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURI-1.html";
    private static final String DOC_TWO_NAME = "https://nowina.lu/pub/JAdES/ObjectIdByURI-2.html";

    private JAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSign;
    private JAdESService jadesService;

    @BeforeEach
    public void init() throws Exception {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURI-1.html");
        documentOne.setName(DOC_ONE_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURI-2.html");
        documentTwo.setName(DOC_TWO_NAME);
        documentsToSign = Arrays.asList(documentOne, documentTwo);

        jadesService = new JAdESService(getOfflineCertificateVerifier());

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        assertEquals(1, signatures.size());

        JAdESSignature signature = (JAdESSignature) signatures.get(0);
        JWS jws = signature.getJws();
        Headers headers = jws.getHeaders();

        try {
            Map<String, Object> signedHeaders = JsonUtil.parseJson(headers.getFullHeaderAsJsonString());
            Map sigD = (Map) signedHeaders.get("sigD");
            assertNotNull(sigD);
            List pars = (List) sigD.get("pars");
            assertNotNull(pars);
            assertEquals(2, pars.size());

            boolean firstDocFound = false;
            boolean secondDocFound = false;
            for (Object name : pars) {
                if (DOC_ONE_NAME.equals(name)) {
                    firstDocFound = true;
                } else if (DOC_TWO_NAME.equals(name)) {
                    secondDocFound = true;
                }
            }
            assertTrue(firstDocFound);
            assertTrue(secondDocFound);

        } catch (JoseException e) {
            fail(e);
        }

    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        boolean firstDocFound = false;
        boolean secondDocFound = false;
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(2, signatureScopes.size());
        for (XmlSignatureScope signatureScope : signatureScopes) {
            if (DOC_ONE_NAME.equals(signatureScope.getName())) {
                firstDocFound = true;
            } else if (DOC_TWO_NAME.equals(signatureScope.getName())) {
                secondDocFound = true;
            }
        }
        assertTrue(firstDocFound);
        assertTrue(secondDocFound);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return documentsToSign;
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
        return documentsToSign;
    }

}
