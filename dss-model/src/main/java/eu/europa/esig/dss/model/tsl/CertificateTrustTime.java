package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.timedependent.BaseTimeDependent;

import java.util.Date;
import java.util.Objects;

/**
 * This class defines a validity period during which a certificate is considered as a trust anchor
 *
 */
public class CertificateTrustTime extends BaseTimeDependent {

    /**
     * Empty constructor
     */
    public CertificateTrustTime() {
        super();
    }

    /**
     * Default constructor
     *
     * @param startDate {@link Date} certificate trust start time
     * @param endDate {@link Date} certificate trust end time
     */
    public CertificateTrustTime(final Date startDate, final Date endDate) {
        super(startDate, endDate);
    }

    /**
     * This method verifies whether the {@code controlTime} lies within the certificate trust time range
     *
     * @param controlTime {@link Date} to check
     * @return TRUE if the certificate is trusted during the {@code controlTime}, FALSE otherwise
     */
    public boolean isTrustedAtTime(Date controlTime) {
        return Objects.equals(getDateBefore(getStartDate(), controlTime), getStartDate()) &&
                Objects.equals(getDateAfter(getEndDate(), controlTime), getEndDate());
    }

    /**
     * This method is used to create a joint time period using the current trust time and the given period
     * between {@code startDate} and {@code endDate}.
     * NOTE: the method does not change the current time, but creates a new joint interval
     *
     * @param startDate {@link Date} the time of another period start
     * @param endDate {@link Date} the time of another period end
     * @return {@link CertificateTrustTime}
     */
    public CertificateTrustTime getJointTrustTime(Date startDate, Date endDate) {
        return new CertificateTrustTime(getDateBefore(getStartDate(), startDate), getDateAfter(getEndDate(), endDate));
    }

    private Date getDateBefore(Date dateOne, Date dateTwo) {
        if (dateOne == null) {
            return dateOne;
        } else if (dateTwo == null) {
            return dateTwo;
        } else if (dateOne.before(dateTwo)) {
            return dateOne;
        } else {
            return dateTwo;
        }
    }

    private Date getDateAfter(Date dateOne, Date dateTwo) {
        if (dateOne == null) {
            return dateOne;
        } else if (dateTwo == null) {
            return dateTwo;
        } else if (dateOne.after(dateTwo)) {
            return dateOne;
        } else {
            return dateTwo;
        }
    }

}
