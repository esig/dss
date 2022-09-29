package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Date;
import java.util.Objects;

/**
 * This predicate is used to filter keys based on the validity range of the certificate
 *
 */
public class ValidAtTimeKeyEntryPredicate implements DSSKeyEntryPredicate {

    /** Represents the validation time to check the certificate validity range against */
    private final Date validationTime;

    /**
     * Constructor instantiating the object with the current time
     */
    public ValidAtTimeKeyEntryPredicate() {
        this(new Date());
    }

    /**
     * Default constructor with the defined validation time
     *
     * @param validationTime {@link Date} representing a time to check the validity range of the certificate against
     *                                (i.e. notBefore - notAfter). If the time is outside the validity range for
     *                                the corresponding certificate, the key is not returned.
     */
    public ValidAtTimeKeyEntryPredicate(Date validationTime) {
        Objects.requireNonNull(validationTime, "Validation time cannot be null!");
        this.validationTime = validationTime;
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
        if (certificate != null) {
            return validationTime.compareTo(certificate.getNotBefore()) >= 0 &&
                    validationTime.compareTo(certificate.getNotAfter()) <= 0;
        }
        return false;
    }

}
