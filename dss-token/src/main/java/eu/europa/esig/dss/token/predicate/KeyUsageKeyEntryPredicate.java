package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to filter private key predicates based on the certificate KeyUsage attribute value
 *
 */
public class KeyUsageKeyEntryPredicate implements DSSKeyEntryPredicate {

    /** Collection of key usages to be accepted */
    private final Collection<KeyUsageBit> keyUsages;

    /**
     * Default constructor
     *
     * @param keyUsages array of {@link KeyUsageBit}s to be accepted
     */
    public KeyUsageKeyEntryPredicate(KeyUsageBit... keyUsages) {
        Objects.requireNonNull(keyUsages, "KeyUsage cannot be null!");
        this.keyUsages = Arrays.asList(keyUsages);
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
        if (certificate != null) {
            List<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
            if (keyUsageBits != null && !keyUsageBits.isEmpty()) {
                for (KeyUsageBit keyUsageBit : keyUsageBits) {
                    if (keyUsages.contains(keyUsageBit)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

}
