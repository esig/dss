package eu.europa.ec.markt.dss.validation102853;

/**
 * This class holds the result of the timestamp's signature validation.
 *
 * To be valid the timestamp must be signed by the given certificate and the certificate must be the one referred to by the SigningCertificate attribute included in the hashed
 * attributes of the timestamp's signature. The certificate must also have the ExtendedKeyUsageExtension with only KeyPurposeId.id_kp_timeStamping and have been valid at the time
 * the timestamp was created.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class TimestampValidation {

    private TimestampValidity timestampValidity = TimestampValidity.NOT_YET_VERIFIED;

    public TimestampValidation(final TimestampValidity timestampValidity) {

        this.timestampValidity = timestampValidity;
    }

    public boolean isValid() {
        return TimestampValidity.VALID.equals(timestampValidity);
    }

    public TimestampValidity getValidity() {
        return timestampValidity;
    }
}
