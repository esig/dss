package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.Abstract19322CryptographicSuite;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.json.JsonObjectWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This class wraps an ETSI TS 119 312/322 JSON cryptographic suite policy
 *
 */
public class CryptographicSuiteJsonWrapper extends Abstract19322CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicSuiteJsonWrapper.class);

    /** Wrapped root element of ETSI TS 119 322 JSON schema */
    private final JsonObjectWrapper securitySuitabilityPolicy;

    /**
     * Default constructor to create an instance of {@code CryptographicSuiteJsonWrapper}
     *
     * @param securitySuitabilityPolicy {@link JsonObjectWrapper}
     */
    public CryptographicSuiteJsonWrapper(JsonObjectWrapper securitySuitabilityPolicy) {
        Objects.requireNonNull(securitySuitabilityPolicy, "securitySuitabilityPolicy cannot be null!");
        this.securitySuitabilityPolicy = securitySuitabilityPolicy;
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        final Map<DigestAlgorithm, Date> digestAlgorithmsMap = new LinkedHashMap<>();
        List<JsonObjectWrapper> algorithmList = securitySuitabilityPolicy.getAsList(CryptographicSuiteJsonConstraints.ALGORITHM);
        for (JsonObjectWrapper algorithm : algorithmList) {
            JsonObjectWrapper algorithmIdentifier = algorithm.getAsObject(CryptographicSuiteJsonConstraints.ALGORITHM_IDENTIFIER);
            DigestAlgorithm digestAlgorithm = getDigestAlgorithm(algorithmIdentifier);
            if (digestAlgorithm == null) {
                continue;
            }

            List<JsonObjectWrapper> evaluationList = algorithm.getAsList(CryptographicSuiteJsonConstraints.EVALUATION);
            Date endDate = getDigestAlgorithmEndDate(evaluationList);
            digestAlgorithmsMap.put(digestAlgorithm, endDate);

        }
        return digestAlgorithmsMap;
    }

    private DigestAlgorithm getDigestAlgorithm(JsonObjectWrapper algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        // NOTE: Name is not evaluated, it is not supposed to be machine-processable
        String objectIdentifier = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.OBJECT_IDENTIFIER);
        if (objectIdentifier != null && !objectIdentifier.isEmpty()) {
            try {
                return DigestAlgorithm.forOID(objectIdentifier);
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        // optional
        String uri = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.URI);
        if (uri != null && !uri.isEmpty()) {
            try {
                return DigestAlgorithm.forXML(uri);
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        return null;
    }

    private Date getDigestAlgorithmEndDate(List<JsonObjectWrapper> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return null;
        }
        Date latestEndDate = null;
        for (JsonObjectWrapper evaluation : evaluations) {
            JsonObjectWrapper validity = evaluation.getAsObject(CryptographicSuiteJsonConstraints.VALIDITY);
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            if (endDate == null) {
                // No EndDate -> consider as a still valid algorithm
                return null;
            } else {
                if (latestEndDate == null || latestEndDate.before(endDate)) {
                    latestEndDate = endDate;
                }
            }
        }
        return latestEndDate;
    }

    @Override
    public Map<EncryptionAlgorithmWithMinKeySize, Date> getAcceptableEncryptionAlgorithmsWithExpirationDates() {
        final Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsMap = new LinkedHashMap<>();
        List<JsonObjectWrapper> algorithmList = securitySuitabilityPolicy.getAsList(CryptographicSuiteJsonConstraints.ALGORITHM);
        for (JsonObjectWrapper algorithm : algorithmList) {
            JsonObjectWrapper algorithmIdentifier = algorithm.getAsObject(CryptographicSuiteJsonConstraints.ALGORITHM_IDENTIFIER);
            EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(algorithmIdentifier);
            if (encryptionAlgorithm == null) {
                continue;
            }

            List<JsonObjectWrapper> evaluationList = algorithm.getAsList(CryptographicSuiteJsonConstraints.EVALUATION);
            Map<Integer, Date> endDatesMap = getEncryptionAlgorithmKeySizeEndDates(encryptionAlgorithm, evaluationList);
            for (Integer keySize : endDatesMap.keySet()) {
                EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize = new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, keySize);
                encryptionAlgorithmsMap.put(encryptionAlgorithmWithMinKeySize, endDatesMap.get(keySize));
            }
        }
        return encryptionAlgorithmsMap;
    }

    private EncryptionAlgorithm getEncryptionAlgorithm(JsonObjectWrapper algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        String objectIdentifier = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.OBJECT_IDENTIFIER);
        if (objectIdentifier != null && !objectIdentifier.isEmpty()) {
            // Can be defined as EncryptionAlgorithm or SignatureAlgorithm
            try {
                return EncryptionAlgorithm.forOID(objectIdentifier);
            } catch (IllegalArgumentException e) {
                // continue silently
            }
            try {
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(objectIdentifier);
                return signatureAlgorithm.getEncryptionAlgorithm();
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        // optional
        String uri = algorithmIdentifier.getAsString(CryptographicSuiteJsonConstraints.URI);
        if (uri != null && !uri.isEmpty()) {
            try {
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(uri);
                return signatureAlgorithm.getEncryptionAlgorithm();
            } catch (IllegalArgumentException e) {
                // continue silently
            }
        }
        return null;
    }

    private Map<Integer, Date> getEncryptionAlgorithmKeySizeEndDates(EncryptionAlgorithm encryptionAlgorithm, List<JsonObjectWrapper> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return null;
        }
        final Map<Integer, Date> keySizeEndDates = new LinkedHashMap<>();
        for (JsonObjectWrapper evaluation : evaluations) {
            List<JsonObjectWrapper> parameters = evaluation.getAsList(CryptographicSuiteJsonConstraints.PARAMETER);
            Integer keySize = getKeySize(encryptionAlgorithm, parameters);

            JsonObjectWrapper validity = evaluation.getAsObject(CryptographicSuiteJsonConstraints.VALIDITY);
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            keySizeEndDates.put(keySize, endDate);
        }
        return keySizeEndDates;
    }

    private Integer getKeySize(EncryptionAlgorithm encryptionAlgorithm, List<JsonObjectWrapper> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return 0;
        }

        Integer keySize = 0;
        for (JsonObjectWrapper parameter : parameters) {
            Number maxKeyLength = parameter.getAsNumber(CryptographicSuiteJsonConstraints.MAX);
            if (maxKeyLength != null) {
                LOG.debug("The Max key length parameter is not supported. The value has been skipped.");
            }

            // first come, first served logic
            String name = parameter.getAsString(CryptographicSuiteJsonConstraints.NAME);
            Number minKeyLength = parameter.getAsNumber(CryptographicSuiteJsonConstraints.MIN);
            if (minKeyLength == null) {
                minKeyLength = 0;
            }
            if (MODULES_LENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.RSA.isEquivalent(encryptionAlgorithm)) {
                    return minKeyLength.intValue();
                }

            } else if (PLENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.DSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.EDDSA.isEquivalent(encryptionAlgorithm)) {
                    return minKeyLength.intValue();
                }

            } else if (QLENGTH_PARAMETER.equals(name)) {
                // process silently (not supported)

            } else {
                LOG.warn("Unknown Algorithms Parameter type '{}'!", name);
            }

            // if no known attribute is encountered, return the available key size
            keySize = minKeyLength.intValue();
        }
        return keySize;
    }

    private Date getValidityEndDate(JsonObjectWrapper validity) {
        Date startDate = validity.getAsDate(CryptographicSuiteJsonConstraints.START);
        if (startDate != null) {
            LOG.debug("The Start date is not supported. The values has been skipped.");
        }
        return validity.getAsDate(CryptographicSuiteJsonConstraints.END);
    }

    @Override
    public Date getCryptographicSuiteUpdateDate() {
        return securitySuitabilityPolicy.getAsDateTime(CryptographicSuiteJsonConstraints.POLICY_ISSUE_DATE);
    }

}
