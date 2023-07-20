package eu.europa.esig.dss.validation.process.qualification.timestamp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualificationAtTime;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.GrantedStatusCheck;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.RelatedToMraEnactedTrustServiceCheck;
import eu.europa.esig.dss.validation.process.qualification.timestamp.checks.GrantedStatusAtProductionTimeCheck;
import eu.europa.esig.dss.validation.process.qualification.timestamp.checks.QTSTCheck;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServiceFilter;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.TrustServicesFilterFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Verifies timestamp's qualification at the given time
 *
 */
public class TimestampQualificationAtTimeBlock extends Chain<XmlValidationTimestampQualificationAtTime> {

    /** The time type to get the qualification at */
    private final ValidationTime validationTime;

    /** The time to check against */
    private final Date date;

    /** The timestamp to be validated */
    private final TimestampWrapper timestamp;

    /** List of matching TrustServices */
    private final List<TrustServiceWrapper> acceptableServices;

    /** The determined timestamp qualification */
    private TimestampQualification tstQualif = TimestampQualification.NA;

    /**
     * Constructor for validation at the timestamp generation time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param timestamp {@link TimestampWrapper} qualification of which will be verified
     * @param acceptableServices a list of acceptable {@link TrustServiceWrapper}s
     */
    public TimestampQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime,
                                             TimestampWrapper timestamp, List<TrustServiceWrapper> acceptableServices) {
        this(i18nProvider, validationTime, null, timestamp, acceptableServices);
    }

    /**
     * Constructor with a custom validation {@code date}
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param date {@link Date} validation time
     * @param timestamp {@link TimestampWrapper} qualification of which will be verified
     * @param acceptableServices a list of acceptable {@link TrustServiceWrapper}s
     */
    public TimestampQualificationAtTimeBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date,
                                             TimestampWrapper timestamp, List<TrustServiceWrapper> acceptableServices) {
        super(i18nProvider, new XmlValidationTimestampQualificationAtTime());
        this.validationTime = validationTime;
        this.timestamp = timestamp;
        this.acceptableServices = acceptableServices;

        switch (validationTime) {
            case TIMESTAMP_GENERATION_TIME:
                this.date = timestamp.getProductionTime();
                break;
            case TIMESTAMP_POE_TIME:
                this.date = date;
                break;
            default:
                throw new IllegalArgumentException("Unsupported qualification time : " + validationTime);
        }
    }

    @Override
    protected String buildChainTitle() {
        MessageTag message = MessageTag.TST_QUALIFICATION_AT_TIME;
        MessageTag param = ValidationProcessUtils.getValidationTimeMessageTag(validationTime);
        return i18nProvider.getMessage(message, param);
    }

    @Override
    protected void initChain() {
        List<TrustServiceWrapper> filteredServices = new ArrayList<>(acceptableServices);

        ChainItem<XmlValidationTimestampQualificationAtTime> item = null;

        // Execute only for Trusted Lists with defined MRA
        if (isMRAEnactedForTrustedList(filteredServices)) {
            TrustServiceFilter filter = TrustServicesFilterFactory.createMRAEnactedFilter();
            filteredServices = filter.filter(filteredServices);

            item = firstItem = hasMraEnactedTrustService(filteredServices);
        }

        // 1. filter by service for QTST
        TrustServiceFilter filter = TrustServicesFilterFactory.createFilterByQTST();
        List<TrustServiceWrapper> qtstServices = filter.filter(filteredServices);

        if (item == null) {
            item = firstItem = hasQTST(qtstServices);
        } else {
            item = item.setNextItem(hasQTST(qtstServices));
        }

        // 2. filter by granted
        filter = TrustServicesFilterFactory.createFilterByGranted();
        List<TrustServiceWrapper> grantedServices = filter.filter(qtstServices);

        item = item.setNextItem(hasGrantedStatus(grantedServices));

        // 3. filter by date (generation time)
        filter = TrustServicesFilterFactory.createFilterByDate(date);
        List<TrustServiceWrapper> grantedAtDateServices = filter.filter(grantedServices);

        item = item.setNextItem(hasGrantedStatusAtDate(grantedAtDateServices));

        // Determine qualification status
        if (Utils.isCollectionNotEmpty(grantedAtDateServices)) {
            tstQualif = TimestampQualification.QTSA;
        } else {
            tstQualif = TimestampQualification.TSA;
        }

    }

    @Override
    protected void addAdditionalInfo() {
        //setIndication();
        result.setTimestampQualification(tstQualif);
        result.setValidationTime(validationTime);
        result.setDateTime(date);
    }

    private ChainItem<XmlValidationTimestampQualificationAtTime> hasMraEnactedTrustService(List<TrustServiceWrapper> services) {
        return new RelatedToMraEnactedTrustServiceCheck<>(i18nProvider, result, services, getFailLevelConstraint());
    }

    private ChainItem<XmlValidationTimestampQualificationAtTime> hasQTST(List<TrustServiceWrapper> services) {
        return new QTSTCheck<>(i18nProvider, result, services, getFailLevelConstraint());
    }

    private ChainItem<XmlValidationTimestampQualificationAtTime> hasGrantedStatus(List<TrustServiceWrapper> services) {
        return new GrantedStatusCheck<>(i18nProvider, result, services, getFailLevelConstraint());
    }

    private ChainItem<XmlValidationTimestampQualificationAtTime> hasGrantedStatusAtDate(List<TrustServiceWrapper> services) {
        return new GrantedStatusAtProductionTimeCheck<>(i18nProvider, result, services, getFailLevelConstraint());
    }

    private boolean isMRAEnactedForTrustedList(List<TrustServiceWrapper> trustServices) {
        for (TrustServiceWrapper trustService : trustServices) {
            if (Utils.isTrue(trustService.getTrustedList().isMra())) {
                return true;
            }
        }
        return false;
    }

}
