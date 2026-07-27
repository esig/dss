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
package eu.europa.esig.dss.validation.process.bbb.aov;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.aov.cc.DigestAlgorithmCryptographicChecker;
import eu.europa.esig.dss.validation.process.bbb.aov.cc.checks.DigestMatcherCryptographicCheckerResultCheck;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enables validation of a digest matcher chain
 *
 * @param <T> {@link AlgorithmObsolescenceValidation}
 */
public abstract class DigestAlgorithmObsolescenceValidation<T> extends AlgorithmObsolescenceValidation<T> {

    /** Contains a list of digest matcher types to be ignored in case of unknown digest algorithm */
    private static List<DigestMatcherType> digestMatcherTypesToIgnore;

    static {
        digestMatcherTypesToIgnore = Arrays.asList(
                DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE,
                DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT,
                DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP,
                DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE,
                DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE,
                DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM
        );
    }

    /**
     * Common constructor
     *
     * @param i18nProvider     the access to translations
     * @param token            instance of {@link AbstractTokenProxy} to be processed
     * @param context          {@link Context} validation context
     * @param validationDate   {@link Date} validation time
     * @param validationPolicy {@link ValidationPolicy} to be used during the validation
     */
    protected DigestAlgorithmObsolescenceValidation(I18nProvider i18nProvider, T token, Context context, Date validationDate, ValidationPolicy validationPolicy) {
        super(i18nProvider, token, context, validationDate, validationPolicy);
    }

    /**
     * Builds a chain of crypto checks to be executed on a signature's references (digest matchers)
     *
     * @param item {@link ChainItem} to chain new checks to
     * @param digestMatchers a list of {@link XmlDigestMatcher}s
     * @param tokenId {@link String} id of the token
     * @return {@link ChainItem}
     */
    protected ChainItem<XmlAOV> buildDigestMatchersValidationChain(ChainItem<XmlAOV> item, List<XmlDigestMatcher> digestMatchers, String tokenId) {
        if (Utils.isCollectionEmpty(digestMatchers)) {
            return item;
        }

        XmlCryptographicValidation cryptographicValidation = null;

        List<XmlDigestMatcher> digestMatchersToProcess = getDigestMatchersToProcess(digestMatchers);
        final Set<DigestAlgorithm> usedDigestAlgorithms = getUsedDigestAlgorithms(digestMatchersToProcess);
        final Set<MessageTag> usedPositions = getUsedPositions(digestMatchersToProcess);
        for (DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {
            for (MessageTag position : usedPositions) {
                List<XmlDigestMatcher> digestMatchersGroup = getDigestMatchersByAlgorithmAndPosition(digestMatchersToProcess, digestAlgorithm, position);
                if (Utils.isCollectionNotEmpty(digestMatchersGroup)) {
                    DigestAlgorithmCryptographicChecker dac = new DigestAlgorithmCryptographicChecker(
                            i18nProvider, digestAlgorithm, validationDate, position, cryptographicSuite);
                    XmlCC dacResult = dac.execute();

                    if (item == null) {
                        item = firstItem = digestAlgorithmCheckResult(digestMatchersGroup, dacResult, cryptographicSuite);
                    } else {
                        item = item.setNextItem(digestAlgorithmCheckResult(digestMatchersGroup, dacResult, cryptographicSuite));
                    }

                    if (cryptographicValidation == null || (isValid(cryptographicValidation) && Indication.PASSED != dacResult.getConclusion().getIndication())) {
                        cryptographicValidation = dacResult.getCryptographicValidation();
                        cryptographicValidation.setConcernedMaterialDescription(getMaterialDescription(digestMatchersGroup));
                    }
                }
            }
        }

        digestMatchersCryptographicValidation = cryptographicValidation;
        if (digestMatchersCryptographicValidation != null) {
            digestMatchersCryptographicValidation.setTokenId(tokenId);
        }

        return item;
    }
    /**
     * This method omits digest matchers that were created for validation purposes but not originally are present in a signature
     *
     * @param digestMatchers a list of {@link XmlDigestMatcher}s
     * @return a list of {@link XmlDigestMatcher}s
     */
    private List<XmlDigestMatcher> getDigestMatchersToProcess(List<XmlDigestMatcher> digestMatchers) {
        final List<XmlDigestMatcher> digestMatchersToProcess = new ArrayList<>();
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.getDigestMethod() != null || !digestMatcherTypesToIgnore.contains(digestMatcher.getType())) {
                digestMatchersToProcess.add(digestMatcher);
            }
        }
        if (Utils.isCollectionEmpty(digestMatchersToProcess)) {
            return digestMatchers; // return original values if no matching entries found
        }
        return digestMatchersToProcess;
    }

    private Set<DigestAlgorithm> getUsedDigestAlgorithms(List<XmlDigestMatcher> digestMatchers) {
        return digestMatchers.stream().map(XmlDigestAlgoAndValue::getDigestMethod).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private Set<MessageTag> getUsedPositions(List<XmlDigestMatcher> digestMatchers) {
        return digestMatchers.stream().map(ValidationProcessUtils::getDigestMatcherCryptoPosition).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private List<XmlDigestMatcher> getDigestMatchersByAlgorithmAndPosition(
            List<XmlDigestMatcher> digestMatchers, DigestAlgorithm digestAlgorithm, MessageTag position) {
        if (position == null) {
            return Collections.emptyList();
        }
        return digestMatchers.stream().filter(d ->
                        digestAlgorithm == d.getDigestMethod() && position == ValidationProcessUtils.getDigestMatcherCryptoPosition(d)
                                && DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE != d.getType()) // COUNTER_SIGNED_SIGNATURE_VALUE is an internal variable
                .collect(Collectors.toList());
    }

    private ChainItem<XmlAOV> digestAlgorithmCheckResult(List<XmlDigestMatcher> digestMatchers, XmlCC ccResult,
                                                         CryptographicSuite constraint) {
        MessageTag position = ValidationProcessUtils.getDigestMatcherCryptoPosition(digestMatchers);
        return new DigestMatcherCryptographicCheckerResultCheck<>(i18nProvider, result, validationDate, position,
                getReferenceNames(digestMatchers), ccResult, constraint);
    }

    private String getMaterialDescription(List<XmlDigestMatcher> digestMatchers) {
        List<String> referenceNames = getReferenceNames(digestMatchers);
        if (Utils.isCollectionNotEmpty(referenceNames)) {
            return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_NAME, position, Utils.joinStrings(referenceNames, ", "));
        }
        return i18nProvider.getMessage(position);
    }

    private List<String> getReferenceNames(List<XmlDigestMatcher> digestMatchers) {
        return digestMatchers.stream().map(d -> d.getId() != null ? d.getId() : d.getUri() != null ? d.getUri() : d.getDocumentName())
                .filter(Objects::nonNull).collect(Collectors.toList());
    }

}
