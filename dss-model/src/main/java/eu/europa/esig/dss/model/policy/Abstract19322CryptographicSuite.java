package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;

import java.util.ArrayList;
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
    private LevelRule globalLevel;

    /** Defines execution level of the acceptability of encryption algorithms check */
    private LevelRule acceptableEncryptionAlgorithmsLevel;

    /** Defines execution level of the acceptability of the  encryption algorithms' key length check */
    private LevelRule acceptableEncryptionAlgorithmsMinKeySizeLevel;

    /** Defines execution level of the acceptability of digest algorithms check */
    private LevelRule acceptableDigestAlgorithmsLevel;

    /** Defines execution level of the algorithms expiration check */
    private LevelRule algorithmsExpirationDateLevel;

    /** Defines execution level of the algorithms expiration check with expiration occurred after the update of the cryptographic suite */
    private LevelRule algorithmsExpirationTimeAfterPolicyUpdateLevel;

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

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        return new ArrayList<>(getAcceptableDigestAlgorithmsWithExpirationDates().keySet());
    }

    @Override
    public List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms() {
        return getAcceptableEncryptionAlgorithmsWithMinKeySizes().stream()
                .map(EncryptionAlgorithmWithMinKeySize::getEncryptionAlgorithm).collect(Collectors.toList());
    }

    @Override
    public List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes() {
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
        return encryptionAlgorithmWithMinKeySizesMap.entrySet().stream()
                .map(e -> new EncryptionAlgorithmWithMinKeySize(e.getKey(), e.getValue())).collect(Collectors.toList());
    }

}
