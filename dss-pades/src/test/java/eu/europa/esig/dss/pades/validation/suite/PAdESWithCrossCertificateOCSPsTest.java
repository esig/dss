package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.reports.Reports;

import java.util.Iterator;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESWithCrossCertificateOCSPsTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/PAdESWithCrossCertificateOCSP.pdf"));
    }

    @Override
    protected void checkEquivalentCertificates(Reports reports, XmlBasicBuildingBlocks bbb) {
        super.checkEquivalentCertificates(reports, bbb);

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        boolean equivalentCertsFound = false;
        for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
            for (CertificateWrapper candidateCert : diagnosticData.getUsedCertificates()) {
                if (!certificateWrapper.getId().equals(candidateCert.getId()) &&
                        certificateWrapper.getEntityKey().equals(candidateCert.getEntityKey())) {
                    equivalentCertsFound = true;
                }
            }
        }
        assertTrue(equivalentCertsFound);
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
        assertEquals(2, allRevocationData.size());

        Iterator<RevocationWrapper> iterator = allRevocationData.iterator();
        RevocationWrapper firstRevocationData = iterator.next();
        RevocationWrapper secondRevocationData = iterator.next();

        assertNotEquals(firstRevocationData.getSigningCertificate().getId(), secondRevocationData.getSigningCertificate().getId());
        assertEquals(firstRevocationData.getSigningCertificate().getEntityKey(), secondRevocationData.getSigningCertificate().getEntityKey());
    }

}
