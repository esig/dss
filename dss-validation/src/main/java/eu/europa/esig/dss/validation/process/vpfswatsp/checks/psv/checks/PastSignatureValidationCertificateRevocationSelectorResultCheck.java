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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevocationSelectorResultCheck;

/**
 * Verifies the validation result of a {@code PastSignatureValidationCertificateRevocationSelector}
 *
 */
public class PastSignatureValidationCertificateRevocationSelectorResultCheck extends CertificateRevocationSelectorResultCheck<XmlPSV> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       the result
     * @param crsResult    {@link XmlCRS}
     * @param constraint   {@link LevelRule}
     */
    public PastSignatureValidationCertificateRevocationSelectorResultCheck(
            I18nProvider i18nProvider, XmlPSV result, XmlCRS crsResult, LevelRule constraint) {
        super(i18nProvider, result, crsResult, constraint);
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.PSV_CRS;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (Utils.isCollectionNotEmpty(crsResult.getAcceptableRevocationId())) {
            return i18nProvider.getMessage(MessageTag.ACCEPTABLE_REVOCATION, crsResult.getAcceptableRevocationId());
        }
        return null;
    }

}
