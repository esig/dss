package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
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
 * This class contains supporting methods for processing a {@code eu.europa.esig.dss.model.policy.CryptographicSuite}
 *
 */
public final class CryptographicSuiteUtils {

    /**
     * Singleton
     */
    private CryptographicSuiteUtils() {
        // empty
    }

    /**
     * Checks if the given {@link EncryptionAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isEncryptionAlgorithmReliable(CryptographicSuite cryptographicSuite, EncryptionAlgorithm encryptionAlgorithm) {
        if (cryptographicSuite == null) {
            return true;
        }
        return encryptionAlgorithm != null && cryptographicSuite.getAcceptableEncryptionAlgorithms().contains(encryptionAlgorithm);
    }

    /**
     * Checks if the given {@link DigestAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param digestAlgorithm {@link DigestAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isDigestAlgorithmReliable(CryptographicSuite cryptographicSuite, DigestAlgorithm digestAlgorithm) {
        if (cryptographicSuite == null) {
            return true;
        }
        if (digestAlgorithm != null) {
            for (DigestAlgorithm acceptableDigestAlgorithm : cryptographicSuite.getAcceptableDigestAlgorithms()) {
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
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check key length for
     * @param keyLength {@link String} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isEncryptionAlgorithmWithKeySizeReliable(CryptographicSuite cryptographicSuite,
                                                                   EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return isEncryptionAlgorithmWithKeySizeReliable(cryptographicSuite, encryptionAlgorithm, keySize);
    }

    /**
     * Checks if the {code keyLength} for {@link EncryptionAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check key length for
     * @param keySize {@link Integer} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isEncryptionAlgorithmWithKeySizeReliable(CryptographicSuite cryptographicSuite,
                                                                   EncryptionAlgorithm encryptionAlgorithm, Integer keySize) {
        if (cryptographicSuite == null) {
            return true;
        }
        boolean foundAlgorithm = false;
        if (encryptionAlgorithm != null && keySize != 0) {
            for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes()) {
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
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to get expiration date for
     * @param keyLength {@link String} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite,
                                         EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return getExpirationDate(cryptographicSuite, encryptionAlgorithm, keySize);
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code algoToSearch} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} to get expiration date for
     * @param keySize {@link Integer} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite,
                                         EncryptionAlgorithm encryptionAlgorithm, Integer keySize) {
        final TreeMap<Integer, Date> dates = new TreeMap<>();

        Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsWithExpirationDates =
                cryptographicSuite.getAcceptableEncryptionAlgorithmsWithExpirationDates();
        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : encryptionAlgorithmsWithExpirationDates.keySet()) {
            if (encryptionAlgorithm == encryptionAlgorithmWithMinKeySize.getEncryptionAlgorithm()) {
                Date expirationDate = encryptionAlgorithmsWithExpirationDates.get(encryptionAlgorithmWithMinKeySize);
                dates.put(encryptionAlgorithmWithMinKeySize.getMinKeySize(), expirationDate);
            }
        }

        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes()) {
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
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param digestAlgorithm {@link DigestAlgorithm} the algorithm to get expiration date for
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite, DigestAlgorithm digestAlgorithm) {
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        return digestAlgorithmsWithExpirationDates.get(digestAlgorithm);
    }

    /**
     * This method returns a list of reliable {@code DigestAlgorithm} according to the current validation policy
     * at the given validation time
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param validationTime {@link Date} to verify against
     * @return a list of {@link DigestAlgorithm}s
     */
    public static List<DigestAlgorithm> getReliableDigestAlgorithmsAtTime(CryptographicSuite cryptographicSuite, Date validationTime) {
        final List<DigestAlgorithm> reliableDigestAlgorithms = new ArrayList<>();

        List<DigestAlgorithm> acceptableDigestAlgorithms = cryptographicSuite.getAcceptableDigestAlgorithms();
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
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
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param validationTime {@link Date} to verify against
     * @return a list of {@link EncryptionAlgorithmWithMinKeySize}s
     */
    public static List<EncryptionAlgorithmWithMinKeySize> getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(
            CryptographicSuite cryptographicSuite, Date validationTime) {
        final Map<EncryptionAlgorithm, Integer> reliableEncryptionAlgorithms = new EnumMap<>(EncryptionAlgorithm.class);
        Set<EncryptionAlgorithm> processedEncryptionAlgorithms = new HashSet<>();

        List<EncryptionAlgorithm> acceptableEncryptionAlgorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();
        Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsWithExpirationDates = 
                cryptographicSuite.getAcceptableEncryptionAlgorithmsWithExpirationDates();
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

        for (EncryptionAlgorithmWithMinKeySize encryptionAlgorithmWithMinKeySize : cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes()) {
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
