package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESWrongSignCertRefTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cms-wrong-sign-cert-ref.p7m");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_LT, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper signatureTst = timestampList.get(0);
        assertNull(signatureTst.getSigningCertificate());
        assertTrue(Utils.isCollectionEmpty(signatureTst.getCertificateChain()));
        assertFalse(signatureTst.isSignatureIntact());
        assertFalse(signatureTst.isSignatureValid());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        TimestampWrapper signatureTst = timestampList.get(0);
        FoundCertificatesProxy foundCertificates = signatureTst.foundCertificates();
        assertEquals(0, foundCertificates.getRelatedCertificates().size());
        assertEquals(3, foundCertificates.getOrphanCertificates().size());
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        List<XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureTimestamps.size());

        XmlTimestamp timestamp = signatureTimestamps.get(0);
        assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
        assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, timestamp.getSubIndication());
    }

}
