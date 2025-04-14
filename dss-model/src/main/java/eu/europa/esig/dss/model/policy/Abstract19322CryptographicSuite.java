package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This class contains common methods for processing XML and JSON TS 119 322 schemas.
 *
 */
public abstract class Abstract19322CryptographicSuite implements CryptographicSuite {

    /** Key size parameter used by RSA algorithms */
    protected static final String MODULES_LENGTH_PARAMETER = "moduluslength";

    /** P Length key size parameter used by DSA algorithms (supported) */
    protected static final String PLENGTH_PARAMETER = "plength";

    /** Q Length key size parameter used by DSA algorithms (not supported) */
    protected static final String QLENGTH_PARAMETER = "qlength";

    /** Defines global execution level of the cryptographic rules */
    private Level globalLevel = Level.FAIL;

    /** Defines execution level of the acceptability of encryption algorithms check */
    private Level acceptableEncryptionAlgorithmsLevel;

    /** Defines execution level of the acceptability of the  encryption algorithms' key length check */
    private Level acceptableEncryptionAlgorithmsMinKeySizeLevel;

    /** Defines execution level of the acceptability of digest algorithms check */
    private Level acceptableDigestAlgorithmsLevel;

    /** Defines execution level of the algorithms expiration check */
    private Level algorithmsExpirationDateLevel;

    /** Defines execution level of the algorithms expiration check with expiration occurred after the update of the cryptographic suite */
    private Level algorithmsExpirationTimeAfterPolicyUpdateLevel = Level.WARN;

    /** Cached list of acceptable digest algorithms */
    private List<DigestAlgorithm> acceptableDigestAlgorithms;

    /** Cached list of acceptable encryption algorithms */
    private List<EncryptionAlgorithm> acceptableEncryptionAlgorithms;

    /** Cached list of acceptable encryption algorithms with corresponding minimum key sizes */
    private List<EncryptionAlgorithmWithMinKeySize> acceptableEncryptionAlgorithmsWithMinKeySizes;

    /** Cached list of acceptable digest algorithms with their expiration dates */
    private Map<DigestAlgorithm, Date> acceptableDigestAlgorithmsWithExpirationDates;

    /** Cached list of acceptable encryption algorithms with their expiration dates */
    private Map<EncryptionAlgorithmWithMinKeySize, Date> acceptableEncryptionAlgorithmsWithExpirationDates;

    /**
     * Sets the global level of the cryptographic constraints.
     * The value is used when the level is not defined for a specific check execution.
     * Default : Level.FAIL (in case of a check failure, the validation process will be interrupted)
     *
     * @param level {@link Level}
     */
    public void setLevel(Level level) {
        this.globalLevel = level;
    }

    /**
     * Sets the execution level for the acceptable digest algorithms check
     *
     * @param acceptableDigestAlgorithmsLevel {@link Level}
     */
    public void setAcceptableDigestAlgorithmsLevel(Level acceptableDigestAlgorithmsLevel) {
        this.acceptableDigestAlgorithmsLevel = acceptableDigestAlgorithmsLevel;
    }

    /**
     * Sets the execution level for the acceptable encryption algorithms check
     *
     * @param acceptableEncryptionAlgorithmsLevel {@link Level}
     */
    public void setAcceptableEncryptionAlgorithmsLevel(Level acceptableEncryptionAlgorithmsLevel) {
        this.acceptableEncryptionAlgorithmsLevel = acceptableEncryptionAlgorithmsLevel;
    }

    /**
     * Sets the execution level for the acceptable minimum key sizes of encryption algorithms check
     *
     * @param acceptableEncryptionAlgorithmsMinKeySizeLevel {@link Level}
     */
    public void setAcceptableEncryptionAlgorithmsMinKeySizeLevel(Level acceptableEncryptionAlgorithmsMinKeySizeLevel) {
        this.acceptableEncryptionAlgorithmsMinKeySizeLevel = acceptableEncryptionAlgorithmsMinKeySizeLevel;
    }

    /**
     * Sets the execution level for checking algorithms expiration
     * 
     * @param algorithmsExpirationDateLevel {@link Level}
     */
    public void setAlgorithmsExpirationDateLevel(Level algorithmsExpirationDateLevel) {
        this.algorithmsExpirationDateLevel = algorithmsExpirationDateLevel;
    }

    /**
     * Sets the execution level for checking algorithms expiration after the validation policy update
     * Default : Level.WARN (warning message is returned in case of expiration of the used cryptographic constraints 
     *                       after the policy update date)
     *
     * @param algorithmsExpirationTimeAfterPolicyUpdateLevel {@link Level}
     */
    public void setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level algorithmsExpirationTimeAfterPolicyUpdateLevel) {
        this.algorithmsExpirationTimeAfterPolicyUpdateLevel = algorithmsExpirationTimeAfterPolicyUpdateLevel;
    }

    @Override
    public Level getAlgoExpirationDateAfterUpdateLevel() {
        return algorithmsExpirationTimeAfterPolicyUpdateLevel;
    }

    @Override
    public Level getLevel() {
        return globalLevel;
    }

    @Override
    public Level getAcceptableEncryptionAlgoLevel() {
        return getLevel(acceptableEncryptionAlgorithmsLevel);
    }

    @Override
    public Level getMiniPublicKeySizeLevel() {
        return getLevel(acceptableEncryptionAlgorithmsMinKeySizeLevel);
    }

    @Override
    public Level getAcceptableDigestAlgoLevel() {
        return getLevel(acceptableDigestAlgorithmsLevel);
    }

    @Override
    public Level getAlgoExpirationDateLevel() {
        return getLevel(algorithmsExpirationDateLevel);
    }

    private Level getLevel(Level level) {
        // returns global level in case of failure
        return level != null ? level : globalLevel;
    }

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        if (acceptableDigestAlgorithms == null) {
            acceptableDigestAlgorithms = new ArrayList<>(getAcceptableDigestAlgorithmsWithExpirationDates().keySet());
        }
        return acceptableDigestAlgorithms;
    }

    @Override
    public List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms() {
        if (acceptableEncryptionAlgorithms == null) {
            acceptableEncryptionAlgorithms = getAcceptableEncryptionAlgorithmsWithMinKeySizes().stream()
                    .map(EncryptionAlgorithmWithMinKeySize::getEncryptionAlgorithm).collect(Collectors.toList());
        }
        return acceptableEncryptionAlgorithms;
    }

    @Override
    public List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes() {
        if (acceptableEncryptionAlgorithmsWithMinKeySizes == null) {
            Map<EncryptionAlgorithm, Integer> encryptionAlgorithmWithMinKeySizesMap = new HashMap<>();
            for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : getAcceptableEncryptionAlgorithmsWithExpirationDates().keySet()) {
                EncryptionAlgorithm encryptionAlgorithm = encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm();
                int keySize = encryptionAlgorithmWithMinKeySize.getMinKeySize();
                Integer minKeySize = encryptionAlgorithmWithMinKeySizesMap.get(encryptionAlgorithm);
                if (minKeySize == null || minKeySize > keySize) {
                    minKeySize = keySize;
                }
                encryptionAlgorithmWithMinKeySizesMap.put(encryptionAlgorithm, minKeySize);
            }
            acceptableEncryptionAlgorithmsWithMinKeySizes = encryptionAlgorithmWithMinKeySizesMap.entrySet().stream()
                    .map(e -> new EncryptionAlgorithmWithMinKeySize(e.getKey(), e.getValue())).collect(Collectors.toList());
        }
        return acceptableEncryptionAlgorithmsWithMinKeySizes;
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        if (acceptableDigestAlgorithmsWithExpirationDates == null) {
            acceptableDigestAlgorithmsWithExpirationDates = buildAcceptableDigestAlgorithmsWithExpirationDates();
        }
        return acceptableDigestAlgorithmsWithExpirationDates;
    }

    @Override
    public Map<EncryptionAlgorithmWithMinKeySize, Date> getAcceptableEncryptionAlgorithmsWithExpirationDates() {
        if (acceptableEncryptionAlgorithmsWithExpirationDates == null) {
            acceptableEncryptionAlgorithmsWithExpirationDates = buildAcceptableEncryptionAlgorithmsWithExpirationDates();
        }
        return acceptableEncryptionAlgorithmsWithExpirationDates;
    }

    /**
     * Builds a list of acceptable digest algorithms with their corresponding expiration times
     *
     * @return a map between {@link DigestAlgorithm}s and their corresponding expiration {@link Date}s
     */
    protected abstract Map<DigestAlgorithm, Date> buildAcceptableDigestAlgorithmsWithExpirationDates();

    /**
     * Builds a list of acceptable encryption algorithms with their corresponding expiration times relatively the key sizes
     *
     * @return a map between {@link EncryptionAlgorithmWithMinKeySize}s and their corresponding expiration {@link Date}s
     */
    protected abstract Map<EncryptionAlgorithmWithMinKeySize, Date> buildAcceptableEncryptionAlgorithmsWithExpirationDates();

}
