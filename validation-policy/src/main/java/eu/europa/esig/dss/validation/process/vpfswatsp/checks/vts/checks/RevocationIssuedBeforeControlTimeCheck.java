/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies if the issuance date of the revocation status information is before control time
 *
 * @param <T> implementation of the block's conclusion
 */
public class RevocationIssuedBeforeControlTimeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Revocation data to check */
    private final RevocationWrapper revocation;

    /** The control time */
    private final Date controlTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param revocation {@link RevocationWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public RevocationIssuedBeforeControlTimeCheck(I18nProvider i18nProvider, T result, RevocationWrapper revocation,
                                                  Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.revocation = revocation;
        this.controlTime = controlTime;
    }

    @Override
    protected boolean process() {
        return revocation.getThisUpdate() != null && revocation.getThisUpdate().before(controlTime);
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_THIS_UPDATE_CONTROL_TIME, revocation.getId(),
                revocation.getThisUpdate() != null ? ValidationProcessUtils.getFormattedDate(revocation.getThisUpdate()) : null,
                ValidationProcessUtils.getFormattedDate(controlTime));
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_HRDBIBCT;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_HRDBIBCT_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return null;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
