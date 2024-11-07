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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Abstract class containing the main logic for PastSignatureValidation result check
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public abstract class AbstractPastTokenValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Past signature validation */
    private final XmlPSV xmlPSV;

    /** Indication */
    private Indication indication;

    /** SubIndication */
    private SubIndication subIndication;

    /** Past signature validation suffix */
    private static final String PSV_BLOCK_SUFFIX = "-PSV";

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param token {@link TokenProxy}
     * @param xmlPSV {@link XmlPSV}
     * @param constraint {@link LevelConstraint}
     */
    protected AbstractPastTokenValidationCheck(I18nProvider i18nProvider, T result,
                                        TokenProxy token, XmlPSV xmlPSV, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + PSV_BLOCK_SUFFIX);
        this.xmlPSV = xmlPSV;
    }

    @Override
    protected boolean process() {
        if (!isValid(xmlPSV)) {
            indication = xmlPSV.getConclusion().getIndication();
            subIndication = xmlPSV.getConclusion().getSubIndication();
            return false;
        }
        return true;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return indication;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return subIndication;
    }

}
