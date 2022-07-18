package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWSCompactDocumentValidator;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.jose4j.jwx.Headers;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithCommitmentTypeQualifierTest extends AbstractJAdESTestSignature {

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private JAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getOfflineCertificateVerifier());
        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        CommonCommitmentType commonCommitmentType = new CommonCommitmentType();
        commonCommitmentType.setOid(CommitmentTypeEnum.ProofOfApproval.getOid());

        CommitmentQualifier asn1CommitmentQualifier = new CommitmentQualifier();
        JsonObject jsonObject = new JsonObject();
        jsonObject.put("Identifier", "1.2.4.5.6");
        jsonObject.put("Declared Time", DSSUtils.formatDateToRFC(new Date()));
        asn1CommitmentQualifier.setContent(new InMemoryDocument(jsonObject.toJSONString().getBytes()));

        CommitmentQualifier stringCommitmentQualifier = new CommitmentQualifier();
        stringCommitmentQualifier.setContent(new InMemoryDocument(CommitmentTypeEnum.ProofOfApproval.getUri().getBytes()));

        commonCommitmentType.setCommitmentTypeQualifiers(asn1CommitmentQualifier, stringCommitmentQualifier);

        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(commonCommitmentType));
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        JWSCompactDocumentValidator validator = new JWSCompactDocumentValidator(new InMemoryDocument(byteArray));
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        JAdESSignature signature = (JAdESSignature) signatures.get(0);
        Headers headers = signature.getJws().getHeaders();
        Object commitmentType = headers.getObjectHeaderValue(JAdESHeaderParameterNames.SR_CMS);
        assertNotNull(commitmentType);
        assertTrue(commitmentType instanceof List);

        List<?> commTypes = (List<?>) commitmentType;
        assertEquals(1, commTypes.size());

        Object commType = commTypes.get(0);
        assertTrue(commType instanceof Map);

        Map<?, ?> commitmentTypeMap = (Map<?, ?>) commType;

        Object identifier = commitmentTypeMap.get(JAdESHeaderParameterNames.COMM_ID);
        assertNotNull(identifier);
        assertTrue(identifier instanceof Map);
        assertEquals("urn:oid:" + CommitmentTypeEnum.ProofOfApproval.getOid(), ((Map<?, ?>) identifier).get("id"));

        Object qualifiers = commitmentTypeMap.get(JAdESHeaderParameterNames.COMM_QUALS);
        assertNotNull(qualifiers);
        assertTrue(qualifiers instanceof List);

        List<?> qualifiersList = (List<?>) qualifiers;
        assertEquals(2, qualifiersList.size());

        boolean jsonQualifierFound = false;
        boolean stringQualifierFound = false;
        for (Object qualifier : qualifiersList) {
            assertTrue(qualifier instanceof Map);

            Map<?, ?> qualifierMap = (Map<?, ?>) qualifier;
            if (qualifierMap.get("Identifier") != null) {
                assertEquals("1.2.4.5.6", qualifierMap.get("Identifier"));
                assertNotNull(qualifierMap.get("Declared Time"));
                jsonQualifierFound = true;
            } else {
                assertEquals(CommitmentTypeEnum.ProofOfApproval.getUri(), qualifierMap.values().iterator().next());
                stringQualifierFound = true;
            }
        }
        assertTrue(jsonQualifierFound);
        assertTrue(stringQualifierFound);
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
