package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESLevelBWithContentTimestampCustomDigestAlgoTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setReason("Reason");
        signatureParameters.setLocation("Luxembourg");
        signatureParameters.setReason("DSS testing");
        signatureParameters.setContactInfo("Jira");
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureParameters.setContentTimestampParameters(timestampParameters);

        Exception exception = assertThrows(UnsupportedOperationException.class, () ->
                service.getContentTimestamp(documentToSign, signatureParameters));
        assertEquals("DigestAlgorithm for content timestamp creation shall " +
                "be the same as the one defined in PAdESSignatureParameters!", exception.getMessage());

        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        TimestampToken contentTimestamp = service.getContentTimestamp(documentToSign, signatureParameters);
        signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
    }

    @Override
    protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
        super.checkDigestAlgorithm(diagnosticData);
        assertEquals(DigestAlgorithm.SHA512, diagnosticData.getSignatureDigestAlgorithm(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertEquals(TimestampType.CONTENT_TIMESTAMP, timestampWrapper.getType());

        XmlDigestMatcher messageImprint = timestampWrapper.getMessageImprint();
        assertNotNull(messageImprint);
        assertEquals(DigestAlgorithm.SHA512, messageImprint.getDigestMethod());
        assertTrue(messageImprint.isDataFound());
        assertTrue(messageImprint.isDataIntact());

        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
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
