package eu.europa.esig.dss.asic.cades.timestamp.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCETripleTimestampTest extends AbstractASiCWithCAdESTestValidation {

    @Test
    public void test() throws IOException {
        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
        List<DSSDocument> docs = Arrays.asList(documentToSign, documentToSign2);

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        DSSDocument archiveWithTimestamp = service.timestamp(docs, timestampParameters);
        assertNotNull(archiveWithTimestamp);

        service.setTspSource(getGoodTsaCrossCertification());
        archiveWithTimestamp = service.timestamp(archiveWithTimestamp, timestampParameters);

        service.setTspSource(getSelfSignedTsa());
        archiveWithTimestamp = service.timestamp(archiveWithTimestamp, timestampParameters);
        // archiveWithTimestamp.save("target/triple-tst.sce");

        verify(archiveWithTimestamp);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        int lastTimestampedSignedDataAmount = 0;
        int lastTimestampedCertificatesAmount = -1;
        int lastTimestampedRevocationDataAmount = -1;
        int lastTimestampedTimestampsAmount = -1;
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertEquals(TimestampType.CONTENT_TIMESTAMP, timestampWrapper.getType());

            assertTrue(lastTimestampedSignedDataAmount < timestampWrapper.getTimestampedSignedData().size());
            lastTimestampedSignedDataAmount = timestampWrapper.getTimestampedSignedData().size();

            assertTrue(lastTimestampedCertificatesAmount < timestampWrapper.getTimestampedCertificates().size());
            lastTimestampedCertificatesAmount = timestampWrapper.getTimestampedCertificates().size();

            assertTrue(lastTimestampedRevocationDataAmount < timestampWrapper.getTimestampedRevocations().size());
            lastTimestampedRevocationDataAmount = timestampWrapper.getTimestampedRevocations().size();

            assertTrue(lastTimestampedTimestampsAmount < timestampWrapper.getTimestampedTimestamps().size());
            lastTimestampedTimestampsAmount = timestampWrapper.getTimestampedTimestamps().size();

            FoundRevocationsProxy foundRevocations = timestampWrapper.foundRevocations();
            List<RelatedRevocationWrapper> relatedRevocationData = foundRevocations.getRelatedRevocationData();
            if (Utils.isCollectionNotEmpty(relatedRevocationData)) {
                CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
                List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
                assertEquals(relatedRevocationData.size(), certificateRevocationData.size());
                assertEquals(relatedRevocationData.get(0).getId(), certificateRevocationData.get(0).getId());
            }
        }
        assertEquals(5, lastTimestampedSignedDataAmount); // two original files + 3 manifests
        assertEquals(6, lastTimestampedCertificatesAmount);
        assertEquals(2, lastTimestampedRevocationDataAmount);
        assertEquals(2, lastTimestampedTimestampsAmount); // two timestamps
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertTrue(Utils.isCollectionEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationStatus.getMainIndication());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

    @Override
    public void validate() {
        // do nothing
    }

}
