package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;

import java.util.Date;

/**
 * This class fitlers Trusted Services by the related MRA equivalence starting date
 *
 */
public class ServiceByMRAEquivalenceStartingDateFilter extends AbstractTrustedServiceFilter {

    /** Time to filter by */
    private final Date date;

    /**
     * Default constructor
     *
     * @param date {@link Date} to filter TrustedServices with a valid MRA equivalence starting time
     */
    public ServiceByMRAEquivalenceStartingDateFilter(Date date) {
        this.date = date;
    }

    @Override
    boolean isAcceptable(TrustedServiceWrapper service) {
        Date startDate = service.getMraTrustServiceEquivalenceStatusStartingTime();
        if (startDate == null || date == null) {
            return false;
        }

        return !date.before(startDate);
    }

}
