package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * POE provided by a time-stamp token
 *
 */
public class TimestampPOE extends POE {

    /** The timestamp */
    private final TimestampWrapper timestampWrapper;

    /**
     * The constructor to instantiate POE by a timestamp
     *
     * @param timestampWrapper {@link TimestampWrapper}
     */
    public TimestampPOE(TimestampWrapper timestampWrapper) {
        super(getPOETime(timestampWrapper));
        this.timestampWrapper = timestampWrapper;
    }

    private static Date getPOETime(TimestampWrapper timestampWrapper) {
        Objects.requireNonNull(timestampWrapper, "The timestampWrapper must be defined!");
        return timestampWrapper.getProductionTime();
    }

    @Override
    public String getPOEProviderId() {
        return timestampWrapper.getId();
    }

    /**
     * Returns timestamp type if the POE defined by a timestamp
     * NOTE: returns NULL if the POE is defined by a control time
     *
     * @return {@link TimestampType}
     */
    public TimestampType getTimestampType() {
        return timestampWrapper.getType();
    }

    @Override
    public List<XmlTimestampedObject> getPOEObjects() {
        return timestampWrapper.getTimestampedObjects();
    }

    @Override
    public boolean isTokenProvided() {
        return true;
    }

}
