package eu.europa.esig.dss.pades.timestamp.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESTimestampWithAppNameTest extends AbstractPkiFactoryTestValidation<PAdESSignatureParameters, PAdESTimestampParameters> {

    private static final String DSS_APP_NAME = "DSS";

    @Test
    public void test() throws Exception {
        DSSDocument documentToTimestamp = new InMemoryDocument(PAdESLevelBTest.class.getResourceAsStream("/sample.pdf"));

        PAdESService service = new PAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getGoodTsa());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        timestampParameters.setAppName(DSS_APP_NAME);

        DSSDocument timestampedDoc = service.timestamp(documentToTimestamp, timestampParameters);
        assertNotNull(timestampedDoc);

        timestampedDoc.save("target/timestamped.pdf");

        checkAppNamePresence(timestampedDoc);
        verify(timestampedDoc);
    }

    private void checkAppNamePresence(DSSDocument document) {
        byte[] bytes = DSSUtils.toByteArray(document);
        String documentContent = new String(bytes);
        assertTrue(documentContent.contains("/" + PAdESConstants.PROP_BUILD));
        assertTrue(documentContent.contains("/" + PAdESConstants.APP));
        assertTrue(documentContent.contains("/" + DSS_APP_NAME));
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertFalse(Utils.isCollectionNotEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getSignatures()));
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);
        assertEquals(1, diagnosticData.getTimestampList().size());
    }

    @Override
    protected String getSigningAlias() {
        return null;
    }

}
