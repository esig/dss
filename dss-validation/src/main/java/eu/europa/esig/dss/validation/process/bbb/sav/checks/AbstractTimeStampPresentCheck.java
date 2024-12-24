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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Collection;
import java.util.Map;

/**
 * This an abstract class performing analysis if a valid timestamp from the given set is present
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public abstract class AbstractTimeStampPresentCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** List of timestamps */
    private final Collection<XmlTimestamp> xmlTimestamps;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param bbbs map between token ids and corresponding {@code XmlBasicBuildingBlocks}
     * @param xmlTimestamps a collection of {@link XmlTimestamp}s
     * @param constraint {@link LevelConstraint}
     */
    protected AbstractTimeStampPresentCheck(I18nProvider i18nProvider, T result,
                                         Map<String, XmlBasicBuildingBlocks> bbbs, Collection<XmlTimestamp> xmlTimestamps,
                                         LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.bbbs = bbbs;
        this.xmlTimestamps = xmlTimestamps;
    }

    @Override
    protected boolean process() {
        for (TimestampWrapper timestamp : getTimestamps()) {
            XmlValidationProcessBasicTimestamp timestampBasicValidation = getTimestampBasicValidation(timestamp);
            if (timestampBasicValidation != null && ValidationProcessUtils.isAllowedBasicTimestampValidation(timestampBasicValidation.getConclusion())) {
                if (isValidConclusion(timestampBasicValidation.getConclusion())) {
                    return true;
                }
                XmlPSV tstPSV = getPastSignatureValidationForTimestamp(timestamp);
                if (tstPSV != null && isValidConclusion(tstPSV.getConclusion())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns a collection of timestamps to be checked for a presence of a valid one
     *
     * @return collection of {@link TimestampWrapper}s
     */
    protected abstract Collection<TimestampWrapper> getTimestamps();

    private XmlValidationProcessBasicTimestamp getTimestampBasicValidation(TimestampWrapper timestamp) {
        for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
            if (timestamp.getId().equals(xmlTimestamp.getId())) {
                return xmlTimestamp.getValidationProcessBasicTimestamp();
            }
        }
        return null;
    }

    private XmlPSV getPastSignatureValidationForTimestamp(TimestampWrapper timestampWrapper) {
        XmlBasicBuildingBlocks tstBBB = bbbs.get(timestampWrapper.getId());
        if (tstBBB != null) {
            return tstBBB.getPSV();
        }
        return null;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIG_CONSTRAINTS_FAILURE;
    }

}