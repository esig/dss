package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class is used to filter private key predicates based on the certificate ExtendedKeyUsage attribute value
 *
 */
public class ExtendedKeyUsageKeyEntryPredicate implements DSSKeyEntryPredicate {

    /**
     * Collection of extended key usage OID to be accepted.
     */
    private final Collection<String> extendedKeyUsageOIDs;

    /**
     * Default constructor with an array of {@code ExtendedKeyUsage}s to be accepted
     *
     * @param extendedKeyUsages array of {@link KeyUsageBit}s to be accepted
     */
    public ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage... extendedKeyUsages) {
        Objects.requireNonNull(extendedKeyUsages, "ExtendedKeyUsage cannot be null!");
        this.extendedKeyUsageOIDs = Arrays.stream(extendedKeyUsages).filter(Objects::nonNull).map(ExtendedKeyUsage::getOid).collect(Collectors.toSet());
    }

    /**
     * Constructor with an array of ExtendedKeyUsage OIDs to be accepted
     *
     * @param extendedKeyUsageOIDs array of {@link String}s to be accepted
     */
    public ExtendedKeyUsageKeyEntryPredicate(String... extendedKeyUsageOIDs) {
        Objects.requireNonNull(extendedKeyUsageOIDs, "ExtendedKeyUsage OIDs cannot be null!");
        this.extendedKeyUsageOIDs = Arrays.asList(extendedKeyUsageOIDs);
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
        if (certificate != null) {
            List<String> extendedKeyUsages = getExtendedKeyUsages(certificate);
            if (extendedKeyUsages != null && extendedKeyUsages.size() > 0) {
                for (String extendedKeyUsage : extendedKeyUsages) {
                    if (extendedKeyUsageOIDs.contains(extendedKeyUsage)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private List<String> getExtendedKeyUsages(CertificateToken certificateToken) {
        try {
            return certificateToken.getCertificate().getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            throw new DSSException(String.format("Unable to extract ExtendedKeyUsage from a certificate token. " +
                    "Reason : %s", e.getMessage()), e);
        }
    }

}
