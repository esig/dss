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
package eu.europa.esig.dss.model.policy.crypto;

import eu.europa.esig.dss.enumerations.CryptographicSuiteAlgorithmUsage;
import eu.europa.esig.dss.model.policy.CryptographicSuite;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class provides an abstract implementation of an ETSI TS 119 322 cryptographic suite catalogue,
 * providing extraction of cryptographic suites according to the defined usage.
 * This class uses a "smart mapping", decreasing the amount of created objects for various validation scopes,
 * when applicable.
 */
public abstract class CryptographicSuiteCatalogue {

    /**
     * Cached map of created cryptographic suites
     */
    private final Map<List<CryptographicSuiteAlgorithm>, CryptographicSuite> cryptographicSuiteMap;

    /**
     * Metadata extracted from the cryptographic suite document
     */
    private CryptographicSuiteMetadata metadata;

    /**
     * List of cryptographic algorithms and their corresponding validation rules
     * extracted from the cryptographic suite document
     */
    private List<CryptographicSuiteAlgorithm> algorithmList;

    /**
     * Default constructor
     */
    protected CryptographicSuiteCatalogue() {
        this.cryptographicSuiteMap = new HashMap<>();
    }

    /**
     * Gets the metadata
     *
     * @return {@link CryptographicSuiteMetadata}
     */
    protected CryptographicSuiteMetadata getMetadata() {
        if (metadata == null) {
            metadata = buildMetadata();
        }
        return metadata;
    }

    /**
     * Builds the metadata
     *
     * @return {@link CryptographicSuiteMetadata}
     */
    protected abstract CryptographicSuiteMetadata buildMetadata();

    /**
     * Gets the algorithm rules list
     *
     * @return a list of {@link CryptographicSuiteAlgorithm}s
     */
    protected List<CryptographicSuiteAlgorithm> getAlgorithmList() {
        if (algorithmList == null) {
            algorithmList = buildAlgorithmList();
        }
        return algorithmList;
    }

    /**
     * Builds an algorithm rules list
     *
     * @return a list of {@link CryptographicSuiteAlgorithm}s
     */
    protected abstract List<CryptographicSuiteAlgorithm> buildAlgorithmList();

    /**
     * Gets the global {@code CryptographicSuite}
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getCryptographicSuite() {
        List<CryptographicSuiteAlgorithm> algorithms = filterByAlgorithmUsage(getAlgorithmList(), Arrays.asList(
                CryptographicSuiteAlgorithmUsage.SIGN_DATA, CryptographicSuiteAlgorithmUsage.VALIDATE_DATA
        ));
        return getCryptographicSuite(getMetadata(), algorithms);
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of a signature
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getSignatureCryptographicSuite() {
        // same as global constraints
        return getCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of signature certificates
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getSignatureCertificatesCryptographicSuite() {
        List<CryptographicSuiteAlgorithm> algorithms = filterByAlgorithmUsage(getAlgorithmList(), Arrays.asList(
                CryptographicSuiteAlgorithmUsage.SIGN_DATA, CryptographicSuiteAlgorithmUsage.VALIDATE_DATA,
                CryptographicSuiteAlgorithmUsage.SIGN_CERTIFICATES, CryptographicSuiteAlgorithmUsage.VALIDATE_CERTIFICATES
        ));
        return getCryptographicSuite(getMetadata(), algorithms);
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of a counter signature
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getCounterSignatureCryptographicSuite() {
        // same as global constraints
        return getCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of counter signature certificates
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getCounterSignatureCertificatesCryptographicSuite() {
        // same as signature constraints
        return getSignatureCertificatesCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of a key binding signature
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getKeyBindingSignatureCryptographicSuite() {
        // same as global constraints
        return getCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of key binding signature certificates
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getKeyBindingSignatureCertificatesCryptographicSuite() {
        // same as signature constraints
        return getSignatureCertificatesCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of a revocation data
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getRevocationCryptographicSuite() {
        List<CryptographicSuiteAlgorithm> algorithms = filterByAlgorithmUsage(getAlgorithmList(), Arrays.asList(
                CryptographicSuiteAlgorithmUsage.SIGN_DATA, CryptographicSuiteAlgorithmUsage.VALIDATE_DATA,
                CryptographicSuiteAlgorithmUsage.SIGN_OCSP, CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP
        ));
        return getCryptographicSuite(getMetadata(), algorithms);
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of revocation data certificates
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getRevocationCertificatesCryptographicSuite() {
        List<CryptographicSuiteAlgorithm> algorithms = filterByAlgorithmUsage(getAlgorithmList(), Arrays.asList(
                CryptographicSuiteAlgorithmUsage.SIGN_DATA, CryptographicSuiteAlgorithmUsage.VALIDATE_DATA,
                CryptographicSuiteAlgorithmUsage.SIGN_OCSP, CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP,
                CryptographicSuiteAlgorithmUsage.SIGN_CERTIFICATES, CryptographicSuiteAlgorithmUsage.VALIDATE_CERTIFICATES
        ));
        return getCryptographicSuite(getMetadata(), algorithms);
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of a timestamp
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getTimestampCryptographicSuite() {
        List<CryptographicSuiteAlgorithm> algorithms = filterByAlgorithmUsage(getAlgorithmList(), Arrays.asList(
                CryptographicSuiteAlgorithmUsage.SIGN_DATA, CryptographicSuiteAlgorithmUsage.VALIDATE_DATA,
                CryptographicSuiteAlgorithmUsage.SIGN_TIMESTAMPS, CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS
        ));
        return getCryptographicSuite(getMetadata(), algorithms);
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of timestamp data certificates
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getTimestampCertificatesCryptographicSuite() {
        List<CryptographicSuiteAlgorithm> algorithms = filterByAlgorithmUsage(getAlgorithmList(), Arrays.asList(
                CryptographicSuiteAlgorithmUsage.SIGN_DATA, CryptographicSuiteAlgorithmUsage.VALIDATE_DATA,
                CryptographicSuiteAlgorithmUsage.SIGN_TIMESTAMPS, CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS,
                CryptographicSuiteAlgorithmUsage.SIGN_CERTIFICATES, CryptographicSuiteAlgorithmUsage.VALIDATE_CERTIFICATES
        ));
        return getCryptographicSuite(getMetadata(), algorithms);
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of an evidence record
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getEvidenceRecordCryptographicSuite() {
        // no separate handling
        return getCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of an attestation
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getAttestationCryptographicSuite() {
        // no separate handling
        return getCryptographicSuite();
    }

    /**
     * Gets the {@code CryptographicSuite} for validation of an attestation revocation
     *
     * @return {@link CryptographicSuite}
     */
    public CryptographicSuite getAttestationRevocationCryptographicSuite() {
        // no separate handling
        return getCryptographicSuite();
    }

    private List<CryptographicSuiteAlgorithm> filterByAlgorithmUsage(List<CryptographicSuiteAlgorithm> algorithmList,
                                                                     List<CryptographicSuiteAlgorithmUsage> algorithmUsages) {
        final List<CryptographicSuiteAlgorithm> result = new ArrayList<>();
        for (CryptographicSuiteAlgorithm algorithm : algorithmList) {
            algorithm = CryptographicSuiteAlgorithm.copy(algorithm);
            if (algorithm.getEvaluationList() == null || algorithm.getEvaluationList().isEmpty()) {
                result.add(algorithm);
                continue;
            }

            final List<CryptographicSuiteEvaluation> evaluationList = new ArrayList<>();
            for (CryptographicSuiteEvaluation evaluation : algorithm.getEvaluationList()) {
                List<CryptographicSuiteAlgorithmUsage> algorithmUsage = evaluation.getAlgorithmUsage();
                if (algorithmUsage == null || algorithmUsage.isEmpty() || algorithmUsage.stream().anyMatch(algorithmUsages::contains)) {
                    evaluationList.add(evaluation);
                }
            }
            algorithm.setEvaluationList(evaluationList);
            if (!evaluationList.isEmpty()) {
                result.add(algorithm);
            }
        }
        return result;
    }

    /**
     * Builds a cryptographic suite for the given content.
     * If the content is already present within the {@code cryptographicSuiteMap},
     * the method will return an existing entry.
     *
     * @param metadata {@link CryptographicSuiteMetadata}
     * @param algorithmList a list of {@link CryptographicSuiteAlgorithm}s
     * @return {@link CryptographicSuite}
     */
    protected CryptographicSuite getCryptographicSuite(CryptographicSuiteMetadata metadata, List<CryptographicSuiteAlgorithm> algorithmList) {
        return cryptographicSuiteMap.computeIfAbsent(algorithmList, v -> new CryptographicSuite19322(metadata, algorithmList));
    }

}
