package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.MRAStatus;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MRALOTLRepealedInTheFutureWithHistoryEnactedTest extends MRALOTLTest {

    private Date startingDate;

    @BeforeEach
    public void initTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MONTH, 1);
        this.startingDate = calendar.getTime();
    }

    @Override
    protected DSSDocument getOriginalLOTL() {
        return new FileDocument("src/test/resources/mra-zz-lotl-history.xml");
    }

    @Override
    protected Date getTrustServiceEquivalenceStatusStartingTime() {
        return startingDate;
    }

    @Override
    protected String getTrustServiceEquivalenceStatus() {
        return MRAStatus.REPEALED.getUri();
    }

    @Override
    protected String getTrustServiceEquivalenceHistoryStatus() {
        return MRAStatus.ENACTED.getUri();
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.QESIG;
    }

    @Override
    protected void verifySigningCertificate(DiagnosticData diagnosticData) {
        super.verifySigningCertificate(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustedServiceWrapper> trustedServices = signingCertificate.getTrustedServices();
        assertEquals(2, trustedServices.size());

        int enactedCounter = 0;
        int repealedCounter = 0;
        for (TrustedServiceWrapper trustedService : trustedServices) {
            if (trustedService.isEnactedMRA()) {
                ++enactedCounter;
            } else {
                ++repealedCounter;
            }
        }
        assertEquals(1, enactedCounter);
        assertEquals(1, repealedCounter);
    }

    @Override
    protected void verifyCertificates(DiagnosticData diagnosticData) {
        // skip
    }

}
