/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
