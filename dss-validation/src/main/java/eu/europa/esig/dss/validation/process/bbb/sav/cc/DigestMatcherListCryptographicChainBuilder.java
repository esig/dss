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
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestMatcherCryptographicCheckerResultCheck;

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
 * This class extracts used Digest Algorithms across all provides digest matchers and
 * performs validation for the used algorithms
 *
 * @param <T> {@link XmlConstraintsConclusion}
 *
 */
public class DigestMatcherListCryptographicChainBuilder<T extends XmlConstraintsConclusion> {

    /** The internationalization provider */
    private final I18nProvider i18nProvider;

    /** The conclusion result */
    private final T result;

    /** List of DigestMatcher's to be validated */
    private final List<XmlDigestMatcher> digestMatchers;

    /** The used validation time */
    private final Date validationTime;

    /** The used cryptographic constraints */
    private final CryptographicConstraint constraint;

    /** Cached XmlCC */
    private XmlCC concernedCC;

    /** Cached reference names */
    private List<String> concernedMaterial;

    /** Contains a list of digest matcher types to be ignored in case of unknown digest algorithm */
    private static List<DigestMatcherType> digestMatcherTypesToIgnore;

    static {
        digestMatcherTypesToIgnore = Arrays.asList(
                DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE,
                DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT,
                DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP,
                DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE,
                DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE
        );
    }

    /**
     * Default constructor
     *
     * @param i18nProvider the access to translations
     * @param result {@link XmlConstraintsConclusion}
     * @param digestMatchers a list of {@link XmlDigestMatcher}s to be validated
     * @param validationTime {@link Date} the validation time
     * @param constraint {@link CryptographicConstraint}
     */
    public DigestMatcherListCryptographicChainBuilder(final I18nProvider i18nProvider, final T result,
                                                      final List<XmlDigestMatcher> digestMatchers, final Date validationTime,
                                                      final CryptographicConstraint constraint) {
       this.i18nProvider = i18nProvider;
       this.result = result;
       this.digestMatchers = digestMatchers;
       this.validationTime = validationTime;
       this.constraint = constraint;
    }

    /**
     * Executes validation of against all used DigestAlgorithms and builds the validation chain
     * continuing the provided {@code chainItem}
     *
     * @param chainItem returned by the validation process, to be continued with digest matcher checks
     * @return a list of {@link XmlCC}s containing validation results
     */
    public ChainItem<T> build(ChainItem<T> chainItem) {
        if (Utils.isCollectionEmpty(digestMatchers)) {
            return chainItem;
        }

        List<XmlDigestMatcher> digestMatchersToProcess = getDigestMatchersToProcess(digestMatchers);
        final Set<DigestAlgorithm> usedDigestAlgorithms = getUsedDigestAlgorithms(digestMatchersToProcess);
        final Set<MessageTag> usedPositions = getUsedPositions(digestMatchersToProcess);
        for (DigestAlgorithm digestAlgorithm : usedDigestAlgorithms) {
            for (MessageTag position : usedPositions) {
                List<XmlDigestMatcher> digestMatchersGroup = getDigestMatchersByAlgorithmAndPosition(digestMatchersToProcess, digestAlgorithm, position);
                if (Utils.isCollectionNotEmpty(digestMatchersGroup)) {
                    DigestCryptographicChecker dac = new DigestCryptographicChecker(
                            i18nProvider, digestAlgorithm, validationTime, position, constraint);
                    XmlCC dacResult = dac.execute();

                    chainItem = chainItem.setNextItem(digestAlgorithmCheckResult(digestMatchersGroup, dacResult, constraint));

                    if (concernedCC == null || Indication.PASSED != dacResult.getConclusion().getIndication()) {
                        concernedCC = dacResult;
                        concernedMaterial = getReferenceNames(digestMatchersGroup);
                    }
                }
            }
        }
        return chainItem;
    }

    /**
     * Returns a failed XmlCC result, when applicable
     *
     * @return {@link XmlCC} when validation of digest matchers fails, NULL otherwise
     */
    public XmlCC getConcernedCC() {
        return concernedCC;
    }

    /**
     * Returns a failed list of XmlDigestMatcher's, when applicable
     *
     * @return a list of {@link XmlDigestMatcher}s when validation fails, NULL otherwise
     */
    public List<String> getConcernedMaterial() {
        return concernedMaterial;
    }

    /**
     * This method omits digest matchers that were created for validation purposes but not originally are present in a signature
     *
     * @param digestMatchers a list of {@link XmlDigestMatcher}s
     * @return a list of {@link XmlDigestMatcher}s
     */
    private List<XmlDigestMatcher> getDigestMatchersToProcess(List<XmlDigestMatcher> digestMatchers) {
        final List<XmlDigestMatcher> result = new ArrayList<>();
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.getDigestMethod() != null || !digestMatcherTypesToIgnore.contains(digestMatcher.getType())) {
                result.add(digestMatcher);
            }
        }
        if (Utils.isCollectionEmpty(result)) {
            return digestMatchers; // return original values if no matching entries found
        }
        return result;
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

    private ChainItem<T> digestAlgorithmCheckResult(List<XmlDigestMatcher> digestMatchers, XmlCC ccResult,
                                                    CryptographicConstraint constraint) {
        MessageTag position = ValidationProcessUtils.getDigestMatcherCryptoPosition(digestMatchers);
        return new DigestMatcherCryptographicCheckerResultCheck<>(i18nProvider, result, validationTime, position,
                getReferenceNames(digestMatchers), ccResult, constraint);
    }

    private List<String> getReferenceNames(List<XmlDigestMatcher> digestMatchers) {
        return digestMatchers.stream().map(d -> d.getId() != null ? d.getId() : d.getUri() != null ? d.getUri() : d.getDocumentName())
                .filter(Objects::nonNull).collect(Collectors.toList());
    }

}
