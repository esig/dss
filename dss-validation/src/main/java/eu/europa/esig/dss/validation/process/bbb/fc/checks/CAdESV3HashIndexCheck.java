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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;


import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies validity of the ats-hash-index(-v3) attribute present within
 * archive-time-stamp-v3 CAdES unsigned property, according to the EN 319 122-1 specification
 *
 */
public class CAdESV3HashIndexCheck extends ChainItem<XmlFC> {

    /** The timestamp to be validated */
    private final TimestampWrapper timestamp;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param timestamp {@link TimestampWrapper}
     * @param constraint {@link LevelRule}
     */
    public CAdESV3HashIndexCheck(I18nProvider i18nProvider, XmlFC result, TimestampWrapper timestamp, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.timestamp = timestamp;
    }

    @Override
    protected boolean process() {
        if (TimestampType.ARCHIVE_TIMESTAMP == timestamp.getType() &&
                ArchiveTimestampType.CAdES_V3 == timestamp.getArchiveTimestampType()) {
            return timestamp.isAtsHashIndexValid();
        }
        // accept for other timestamp types
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_IAHIV;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_IAHIV_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
