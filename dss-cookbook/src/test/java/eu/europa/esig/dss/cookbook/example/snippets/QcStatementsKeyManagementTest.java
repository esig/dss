package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.QcStatements;
import eu.europa.esig.dss.spi.QcStatementUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.predicate.DSSKeyEntryPredicate;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class QcStatementsKeyManagementTest extends PKIFactoryAccess {

    private String signingAlias;

    @Test
    public void qscdTest() {
        signingAlias = "John Doe";

        try (AbstractKeyStoreTokenConnection token = getToken()) {
            // tag::qcQscdPredicateUsage[]
            // Use of custom DSSKeyEntryPredicate
            token.setKeyEntryPredicate(new QcQSCDKeyEntryPredicate());
            // end::qcQscdPredicateUsage[]
            assertEquals(1, token.getKeys().size());
        }

    }

    @Test
    public void nonQscdTest() {
        signingAlias = "Bob Doe";

        try (AbstractKeyStoreTokenConnection token = getToken()) {
            token.setKeyEntryPredicate(new QcQSCDKeyEntryPredicate());
            assertEquals(0, token.getKeys().size());
        }

    }

    // tag::qcQscdPredicate[]
    // import eu.europa.esig.dss.model.x509.CertificateToken;
    // import eu.europa.esig.dss.model.x509.QcStatements;
    // import eu.europa.esig.dss.spi.QcStatementUtils;
    // import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
    // import eu.europa.esig.dss.token.predicate.DSSKeyEntryPredicate;

    public static class QcQSCDKeyEntryPredicate implements DSSKeyEntryPredicate {

        @Override
        public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
            CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
            if (certificate != null) {
                QcStatements qcStatements = QcStatementUtils.getQcStatements(certificate);
                return qcStatements != null && qcStatements.isQcQSCD();
            }
            return false;
        }

    }
    // end::qcQscdPredicate[]

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
