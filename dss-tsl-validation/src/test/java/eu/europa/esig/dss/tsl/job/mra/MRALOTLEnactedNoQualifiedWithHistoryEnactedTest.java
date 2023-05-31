package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.MRAStatus;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.trustedlist.enums.Assert;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MRALOTLEnactedNoQualifiedWithHistoryEnactedTest extends MRALOTLTest {

    private Date startingDate;

    @BeforeEach
    public void initTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -3);
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
    protected Assert getCertificateContentDeclarationPointingPartyQcComplianceAssertStatus() {
        return Assert.NONE;
    }

    @Override
    protected String getTrustServiceEquivalenceStatus() {
        return MRAStatus.ENACTED.getUri();
    }

    @Override
    protected String getTrustServiceEquivalenceHistoryStatus() {
        return MRAStatus.ENACTED.getUri();
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
        assertEquals(2, enactedCounter);
        assertEquals(0, repealedCounter);
    }

}
