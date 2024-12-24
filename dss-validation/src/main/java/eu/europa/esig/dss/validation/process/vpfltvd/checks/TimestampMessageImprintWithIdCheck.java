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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.TimestampMessageImprintCheck;

/**
 * This class checks a timestamp's message-imprint and returns an Id of the provided token
 *
 * @param <T> implementation of the block's conclusion
 */
public class TimestampMessageImprintWithIdCheck<T extends XmlConstraintsConclusion> extends TimestampMessageImprintCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       {@link XmlSAV}
     * @param timestamp    {@link TimestampWrapper}
     * @param constraint   {@link LevelConstraint}
     */
    public TimestampMessageImprintWithIdCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                              LevelConstraint constraint) {
        super(i18nProvider, result, timestamp, constraint, timestamp.getId());
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                ValidationProcessUtils.getTimestampTypeMessageTag(timestamp.getType()), timestamp.getId(), date);
    }

}
