package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicRules;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * This class contains supporting methods for processing CryptographicRules
 *
 */
public final class CryptographicRulesUtils {

    /**
     * Singleton
     */
    private CryptographicRulesUtils() {
        // empty
    }

    /**
     * Checks if the given {@link EncryptionAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isEncryptionAlgorithmReliable(CryptographicRules cryptographicRules, EncryptionAlgorithm encryptionAlgorithm) {
        if (cryptographicRules == null) {
            return true;
        }
        return encryptionAlgorithm != null && cryptographicRules.getAcceptableEncryptionAlgorithms().contains(encryptionAlgorithm);
    }

    /**
     * Checks if the given {@link DigestAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param digestAlgorithm {@link DigestAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isDigestAlgorithmReliable(CryptographicRules cryptographicRules, DigestAlgorithm digestAlgorithm) {
        if (cryptographicRules == null) {
            return true;
        }
        if (digestAlgorithm != null) {
            for (DigestAlgorithm acceptableDigestAlgorithm : cryptographicRules.getAcceptableDigestAlgorithms()) {
                if (digestAlgorithm == acceptableDigestAlgorithm) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the {code keyLength} for {@link EncryptionAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check key length for
     * @param keyLength {@link String} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isEncryptionAlgorithmWithKeySizeReliable(CryptographicRules cryptographicRules,
                                                            EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return isEncryptionAlgorithmWithKeySizeReliable(cryptographicRules, encryptionAlgorithm, keySize);
    }

    /**
     * Checks if the {code keyLength} for {@link EncryptionAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check key length for
     * @param keySize {@link Integer} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isEncryptionAlgorithmWithKeySizeReliable(CryptographicRules cryptographicRules,
                                                            EncryptionAlgorithm encryptionAlgorithm, Integer keySize) {
        if (cryptographicRules == null) {
            return true;
        }
        boolean foundAlgorithm = false;
        if (encryptionAlgorithm != null && keySize != 0) {
            for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : cryptographicRules.getAcceptableEncryptionAlgorithmsWithMinKeySizes()) {
                int minKeySize = encryptionAlgorithmWithMinKeySize.getMinKeySize();
                if (encryptionAlgorithm == encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm()) {
                    foundAlgorithm = true;
                    if (minKeySize <= keySize) {
                        return true;
                    }
                }
            }
        }
        return !foundAlgorithm;
    }

    private static int parseKeySize(String keyLength) {
        return Utils.isStringDigits(keyLength) ? Integer.parseInt(keyLength) : 0;
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code algoToSearch} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to get expiration date for
     * @param keyLength {@link String} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicRules cryptographicRules,
                                  EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return getExpirationDate(cryptographicRules, encryptionAlgorithm, keySize);
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code algoToSearch} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to get expiration date for
     * @param keySize {@link Integer} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicRules cryptographicRules,
                                  EncryptionAlgorithm encryptionAlgorithm, Integer keySize) {
        final TreeMap<Integer, Date> dates = new TreeMap<>();

        Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsWithExpirationDates =
                cryptographicRules.getAcceptableEncryptionAlgorithmsWithExpirationDates();
        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : encryptionAlgorithmsWithExpirationDates.keySet()) {
            if (encryptionAlgorithm == encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm()) {
                Date expirationDate = encryptionAlgorithmsWithExpirationDates.get(encryptionAlgorithmWithMinKeySize);
                dates.put(encryptionAlgorithmWithMinKeySize.getMinKeySize(), expirationDate);
            }
        }

        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : cryptographicRules.getAcceptableEncryptionAlgorithmsWithMinKeySizes()) {
            if (encryptionAlgorithm == encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm()) {
                Map.Entry<Integer, Date> floorEntry = dates.floorEntry(encryptionAlgorithmWithMinKeySize.getMinKeySize());
                if (floorEntry == null) {
                    Map.Entry<Integer, Date> ceilingEntry = dates.ceilingEntry(encryptionAlgorithmWithMinKeySize.getMinKeySize());
                    if (ceilingEntry != null) {
                        dates.put(encryptionAlgorithmWithMinKeySize.getMinKeySize(), ceilingEntry.getValue());
                    }
                }
            }
        }

        Map.Entry<Integer, Date> floorEntry = dates.floorEntry(keySize);
        if (floorEntry == null) {
            return null;
        } else {
            return floorEntry.getValue();
        }
    }

    /**
     * Gets an expiration date for the digest algorithm with name {@code digestAlgoToSearch}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param digestAlgorithm {@link DigestAlgorithm} the algorithm to get expiration date for
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicRules cryptographicRules, DigestAlgorithm digestAlgorithm) {
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicRules.getAcceptableDigestAlgorithmsWithExpirationDates();
        return digestAlgorithmsWithExpirationDates.get(digestAlgorithm);
    }

    /**
     * This method returns a list of reliable {@code DigestAlgorithm} according to the current validation policy
     * at the given validation time
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param validationTime {@link Date} to verify against
     * @return a list of {@link DigestAlgorithm}s
     */
    public static List<DigestAlgorithm> getReliableDigestAlgorithmsAtTime(CryptographicRules cryptographicRules, Date validationTime) {
        final List<DigestAlgorithm> reliableDigestAlgorithms = new ArrayList<>();

        List<DigestAlgorithm> acceptableDigestAlgorithms = cryptographicRules.getAcceptableDigestAlgorithms();
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicRules.getAcceptableDigestAlgorithmsWithExpirationDates();
        for (DigestAlgorithm digestAlgorithm : digestAlgorithmsWithExpirationDates.keySet()) {
            if (acceptableDigestAlgorithms.contains(digestAlgorithm)) {
                Date expirationDate = digestAlgorithmsWithExpirationDates.get(digestAlgorithm);
                if (isReliableAtTime(expirationDate, validationTime)) {
                    reliableDigestAlgorithms.add(digestAlgorithm);
                }
            }
        }

        for (DigestAlgorithm digestAlgorithm : acceptableDigestAlgorithms) {
            if (!reliableDigestAlgorithms.contains(digestAlgorithm)) {
                Date expirationDate = digestAlgorithmsWithExpirationDates.get(digestAlgorithm);
                if (isReliableAtTime(expirationDate, validationTime)) {
                    reliableDigestAlgorithms.add(digestAlgorithm);
                }
            }
        }

        return reliableDigestAlgorithms;
    }

    private static boolean isReliableAtTime(Date expirationDate, Date validationTime) {
        return expirationDate == null || !expirationDate.before(validationTime);
    }

    /**
     * This method returns a map between reliable {@code EncryptionAlgorithm} according to the current validation policy
     * and their minimal accepted key length at the given time.
     *
     * @param cryptographicRules {@link CryptographicRules}
     * @param validationTime {@link Date} to verify against
     * @return a list of {@link EncryptionAlgorithmWithMinKeySize}s
     */
    public static List<EncryptionAlgorithmWithMinKeySize> getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(
            CryptographicRules cryptographicRules, Date validationTime) {
        final Map<EncryptionAlgorithm, Integer> reliableEncryptionAlgorithms = new EnumMap<>(EncryptionAlgorithm.class);
        Set<EncryptionAlgorithm> processedEncryptionAlgorithms = new HashSet<>();

        List<EncryptionAlgorithm> acceptableEncryptionAlgorithms = cryptographicRules.getAcceptableEncryptionAlgorithms();
        Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsWithExpirationDates = 
                cryptographicRules.getAcceptableEncryptionAlgorithmsWithExpirationDates();
        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : encryptionAlgorithmsWithExpirationDates.keySet()) {
            EncryptionAlgorithm encryptionAlgorithm = encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm();
            int keySize = encryptionAlgorithmWithMinKeySize.getMinKeySize();
            if (acceptableEncryptionAlgorithms.contains(encryptionAlgorithm)) {
                Integer minKeySize = reliableEncryptionAlgorithms.get(encryptionAlgorithm);
                if (minKeySize == null || minKeySize > keySize) {
                    Date expirationDate = encryptionAlgorithmsWithExpirationDates.get(encryptionAlgorithmWithMinKeySize);
                    if (isReliableAtTime(expirationDate, validationTime)) {
                        reliableEncryptionAlgorithms.put(encryptionAlgorithm, keySize);
                    }
                }
            }
            processedEncryptionAlgorithms.add(encryptionAlgorithm);
        }

        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : cryptographicRules.getAcceptableEncryptionAlgorithmsWithMinKeySizes()) {
            EncryptionAlgorithm encryptionAlgorithm = encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm();
            int keySize = encryptionAlgorithmWithMinKeySize.getMinKeySize();
            if (!processedEncryptionAlgorithms.contains(encryptionAlgorithm)) {
                reliableEncryptionAlgorithms.put(encryptionAlgorithm, keySize);

            } else if (reliableEncryptionAlgorithms.containsKey(encryptionAlgorithm)) {
                Integer minKeySize = reliableEncryptionAlgorithms.get(encryptionAlgorithm);
                if (minKeySize == null || minKeySize < keySize) {
                    reliableEncryptionAlgorithms.put(encryptionAlgorithm, keySize);
                }
            }
            processedEncryptionAlgorithms.add(encryptionAlgorithm);
        }

        for (EncryptionAlgorithm encryptionAlgorithm : acceptableEncryptionAlgorithms) {
            if (!processedEncryptionAlgorithms.contains(encryptionAlgorithm)) {
                reliableEncryptionAlgorithms.put(encryptionAlgorithm, 0);
            }
        }

        final List<EncryptionAlgorithmWithMinKeySize> result = new ArrayList<>();
        for (EncryptionAlgorithm encryptionAlgorithm : reliableEncryptionAlgorithms.keySet()) {
            result.add(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, reliableEncryptionAlgorithms.get(encryptionAlgorithm)));
        }
        return result;
    }

}
