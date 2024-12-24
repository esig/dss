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

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;
import java.util.List;

/**
 * Class used to verify a DigestMatcher
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class DigestMatcherCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion>
        extends DigestCryptographicCheckerResultCheck<T> {

    /** The verifying reference names */
    private final List<String> referenceNames;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param validationDate {@link Date}
     * @param position {@link MessageTag}
     * @param referenceNames a list of {@link String}s
     * @param ccResult {@link XmlCC}
     * @param constraint {@link LevelConstraint}
     */
    public DigestMatcherCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, Date validationDate,
                                                        MessageTag position, List<String> referenceNames,
                                                        XmlCC ccResult, LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, position, ccResult, constraint);
        this.referenceNames = referenceNames;
    }

    @Override
    protected String buildAdditionalInfo() {
        String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
        if (isValid(ccResult)) {
            if (Utils.collectionSize(referenceNames) == 0) {
                return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM,
                        ccResult.getVerifiedAlgorithm().getName(), dateTime, position);
            } else if (Utils.collectionSize(referenceNames) == 1) {
                return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAME,
                        ccResult.getVerifiedAlgorithm().getName(), dateTime, position, referenceNames.iterator().next());
            } else {
                return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_NAMES,
                        ccResult.getVerifiedAlgorithm().getName(), dateTime, position, Utils.joinStrings(referenceNames, ", "));
            }
        } else {
            if (Utils.collectionSize(referenceNames) == 0) {
                return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF,
                        getErrorMessage(), dateTime);
            } else if (Utils.collectionSize(referenceNames) == 1) {
                return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF_WITH_NAME,
                        getErrorMessage(), dateTime, referenceNames.iterator().next());
            } else {
                return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF_WITH_NAMES,
                        getErrorMessage(), dateTime, Utils.joinStrings(referenceNames, ", "));
            }
        }
    }

}
