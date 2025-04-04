package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmIdentifierType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.EvaluationType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ParameterType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ValidityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * This class wraps an ETSI TS 119 312/322 XML cryptographic suite policy
 *
 */
public class CryptographicSuiteXmlWrapper implements CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicSuiteXmlWrapper.class);

    /** Key size parameter used by RSA algorithms */
    private static final String MODULES_LENGTH_PARAMETER = "moduluslength";

    /** P Length key size parameter used by DSA algorithms (supported) */
    private static final String PLENGTH_PARAMETER = "plength";

    /** Q Length key size parameter used by DSA algorithms (not supported) */
    private static final String QLENGTH_PARAMETER = "qlength";

    /** Wrapped SecuritySuitabilityPolicyType */
    private final SecuritySuitabilityPolicyType securitySuitabilityPolicy;

    /** Defines global execution level of the cryptographic rules */
    private LevelRule globalLevel;

    /** Defines execution level of the acceptability of encryption algorithms check */
    private LevelRule acceptableEncryptionAlgorithmsLevel;

    /** Defines execution level of the acceptability of the  encryption algorithms' key length check */
    private LevelRule acceptableEncryptionAlgorithmsMinKeySizeLevel;

    /** Defines execution level of the acceptability of digest algorithms check */
    private LevelRule acceptableDigestAlgorithmsLevel;

    /** Defines execution level of the algorithms expiration check */
    private LevelRule algorithmsExpirationDateLevel;

    /** Defines execution level of the algorithms expiration check with expiration occurred after the update of the criptographic suite */
    private LevelRule algorithmsExpirationTimeAfterPolicyUpdateLevel;

    /**
     * Default constructor
     *
     * @param securitySuitabilityPolicy {@link SecuritySuitabilityPolicyType}
     */
    public CryptographicSuiteXmlWrapper(final SecuritySuitabilityPolicyType securitySuitabilityPolicy) {
        this.securitySuitabilityPolicy = securitySuitabilityPolicy;
    }

    /**
     * Sets the global level of the cryptographic constraints.
     * The value is used when the level is not defined for a specific check execution.
     *
     * @param level {@link LevelRule}
     */
    public void setLevel(LevelRule level) {
        this.globalLevel = level;
    }

    /**
     * Sets the execution level for the acceptable encryption algorithms check
     *
     * @param acceptableEncryptionAlgorithmsLevel {@link LevelRule}
     */
    public void setAcceptableEncryptionAlgorithmsLevel(LevelRule acceptableEncryptionAlgorithmsLevel) {
        this.acceptableEncryptionAlgorithmsLevel = acceptableEncryptionAlgorithmsLevel;
    }

    // TODO : continue and maybe switch to Level instead ?
    public void setAcceptableEncryptionAlgorithmsMinKeySizeLevel(LevelRule acceptableEncryptionAlgorithmsMinKeySizeLevel) {
        this.acceptableEncryptionAlgorithmsMinKeySizeLevel = acceptableEncryptionAlgorithmsMinKeySizeLevel;
    }

    public void setAcceptableDigestAlgorithmsLevel(LevelRule acceptableDigestAlgorithmsLevel) {
        this.acceptableDigestAlgorithmsLevel = acceptableDigestAlgorithmsLevel;
    }

    public void setAlgorithmsExpirationDateLevel(LevelRule algorithmsExpirationDateLevel) {
        this.algorithmsExpirationDateLevel = algorithmsExpirationDateLevel;
    }

    public void setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(LevelRule algorithmsExpirationTimeAfterPolicyUpdateLevel) {
        this.algorithmsExpirationTimeAfterPolicyUpdateLevel = algorithmsExpirationTimeAfterPolicyUpdateLevel;
    }

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        return new ArrayList<>(getAcceptableDigestAlgorithmsWithExpirationDates().keySet());
    }

    @Override
    public List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms() {
        // TODO : implement
        return Collections.emptyList();
    }

    @Override
    public List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes() {
        // TODO : implement
        return Collections.emptyList();
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        final Map<DigestAlgorithm, Date> digestAlgorithmsMap = new LinkedHashMap<>();
        for (AlgorithmType algorithmType : securitySuitabilityPolicy.getAlgorithm()) {
            AlgorithmIdentifierType algorithmIdentifier = algorithmType.getAlgorithmIdentifier();
            DigestAlgorithm digestAlgorithm = getDigestAlgorithm(algorithmIdentifier);
            if (digestAlgorithm == null) {
                continue;
            }

            Date endDate = getDigestAlgorithmEndDate(algorithmType.getEvaluation());
            digestAlgorithmsMap.put(digestAlgorithm, endDate);

        }
        return digestAlgorithmsMap;
    }
    
    private DigestAlgorithm getDigestAlgorithm(AlgorithmIdentifierType algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        // NOTE: Name is not evaluated, it is not supposed to be machine-processable
        List<String> objectIdentifiers = algorithmIdentifier.getObjectIdentifier();
        if (objectIdentifiers != null && !objectIdentifiers.isEmpty()) {
            for (String oid : objectIdentifiers) {
                try {
                    // first come, first served policy
                    return DigestAlgorithm.forOID(oid);
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        // optional
        List<String> uris = algorithmIdentifier.getURI();
        if (uris != null && !uris.isEmpty()) {
            for (String uri : uris) {
                try {
                    return DigestAlgorithm.forXML(uri);
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        return null;
    }

    private Date getDigestAlgorithmEndDate(List<EvaluationType> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return null;
        }
        Date latestEndDate = null;
        for (EvaluationType evaluation : evaluations) {
            ValidityType validity = evaluation.getValidity();
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

    private Date getValidityEndDate(ValidityType validity) {
        if (validity.getStart() != null) {
            LOG.debug("The Start date is not supported. The values has been skipped.");
        }
        if (validity.getEnd() != null) {
            XMLGregorianCalendar end = validity.getEnd();
            return end.toGregorianCalendar().getTime();
        }
        return null;
    }

    @Override
    public Map<EncryptionAlgorithmWithMinKeySize, Date> getAcceptableEncryptionAlgorithmsWithExpirationDates() {
        final Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsMap = new LinkedHashMap<>();
        for (AlgorithmType algorithmType : securitySuitabilityPolicy.getAlgorithm()) {
            AlgorithmIdentifierType algorithmIdentifier = algorithmType.getAlgorithmIdentifier();
            EncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(algorithmIdentifier);
            if (encryptionAlgorithm == null) {
                continue;
            }

            Map<Integer, Date> endDatesMap = getEncryptionAlgorithmKeySizeEndDates(encryptionAlgorithm, algorithmType.getEvaluation());
            for (Integer keySize : endDatesMap.keySet()) {
                EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize = new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, keySize);
                encryptionAlgorithmsMap.put(encryptionAlgorithmWithMinKeySize, endDatesMap.get(keySize));
            }

        }
        return encryptionAlgorithmsMap;
    }

    private EncryptionAlgorithm getEncryptionAlgorithm(AlgorithmIdentifierType algorithmIdentifier) {
        if (algorithmIdentifier == null) {
            return null;
        }
        List<String> objectIdentifiers = algorithmIdentifier.getObjectIdentifier();
        if (objectIdentifiers != null && !objectIdentifiers.isEmpty()) {
            for (String oid : objectIdentifiers) {
                // Can be defined as EncryptionAlgorithm or SignatureAlgorithm
                try {
                    // first come, first served policy
                    return EncryptionAlgorithm.forOID(oid);
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
                try {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
                    return signatureAlgorithm.getEncryptionAlgorithm();
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        // optional
        List<String> uris = algorithmIdentifier.getURI();
        if (uris != null && !uris.isEmpty()) {
            for (String uri : uris) {
                try {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(uri);
                    return signatureAlgorithm.getEncryptionAlgorithm();
                } catch (IllegalArgumentException e) {
                    // continue silently
                }
            }
        }
        return null;
    }

    private Map<Integer, Date> getEncryptionAlgorithmKeySizeEndDates(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationType> evaluations) {
        if (evaluations == null || evaluations.isEmpty()) {
            return null;
        }
        final Map<Integer, Date> keySizeEndDates = new LinkedHashMap<>();
        for (EvaluationType evaluation : evaluations) {
            Integer keySize = getKeySize(encryptionAlgorithm, evaluation.getParameter());

            ValidityType validity = evaluation.getValidity();
            if (validity == null) {
                continue;
            }

            Date endDate = getValidityEndDate(validity);
            keySizeEndDates.put(keySize, endDate);
        }
        return keySizeEndDates;
    }

    private Integer getKeySize(EncryptionAlgorithm encryptionAlgorithm, List<ParameterType> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return null;
        }

        Integer keySize = null;
        for (ParameterType parameter : parameters) {
            if (parameter.getMax() != null) {
                LOG.debug("The Max key length parameter is not supported. The value has been skipped.");
            }

            // first come, first served logic
            String name = parameter.getName();
            if (MODULES_LENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.RSA.isEquivalent(encryptionAlgorithm)) {
                    return parameter.getMin();
                }

            } else if (PLENGTH_PARAMETER.equals(name)) {
                if (EncryptionAlgorithm.DSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm) ||
                        EncryptionAlgorithm.EDDSA.isEquivalent(encryptionAlgorithm)) {
                    return parameter.getMin();
                }

            } else if (QLENGTH_PARAMETER.equals(name)) {
                // process silently (not supported)

            } else {
                LOG.warn("Unknown Algorithms Parameter type '{}'!", name);
            }

            // if no known attribute is encountered, return the available key size
            keySize = parameter.getMin();
        }
        return keySize;
    }

    @Override
    public Date getCryptographicSuiteUpdateDate() {
        XMLGregorianCalendar policyIssueDate = securitySuitabilityPolicy.getPolicyIssueDate();
        if (policyIssueDate != null) {
            return policyIssueDate.toGregorianCalendar().getTime();
        }
        return null;
    }

    @Override
    public Level getAlgoExpirationDateAfterUpdateLevel() {
        return null;
    }

    @Override
    public Level getLevel() {
        return globalLevel != null ? globalLevel.getLevel() : null;
    }

    @Override
    public LevelRule getAcceptableEncryptionAlgoLevel() {
        return getLevel(acceptableEncryptionAlgorithmsLevel);
    }

    @Override
    public LevelRule getMiniPublicKeySizeLevel() {
        return getLevel(acceptableEncryptionAlgorithmsMinKeySizeLevel);
    }

    @Override
    public LevelRule getAcceptableDigestAlgoLevel() {
        return getLevel(acceptableDigestAlgorithmsLevel);
    }

    @Override
    public LevelRule getAlgoExpirationDateLevel() {
        return getLevel(algorithmsExpirationDateLevel);
    }

    private LevelRule getLevel(LevelRule level) {
        return level != null ? level : globalLevel;
    }

}
