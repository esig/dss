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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.SignatureAlgorithmWithMinKeySize;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteEvaluation;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteParameter;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class contains supporting methods for processing a {@code eu.europa.esig.dss.model.policy.CryptographicSuite}
 *
 */
public final class CryptographicSuiteUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicSuiteUtils.class);

    /** Key size parameter used by RSA algorithms */
    public static final String MODULES_LENGTH_PARAMETER = "moduluslength";

    /** P Length key size parameter used by DSA algorithms (supported) */
    public static final String PLENGTH_PARAMETER = "plength";

    /** Q Length key size parameter used by DSA algorithms (not supported) */
    public static final String QLENGTH_PARAMETER = "qlength";

    /**
     * Singleton
     */
    private CryptographicSuiteUtils() {
        // empty
    }

    /**
     * Checks if the given {@link SignatureAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to check
     * @return TRUE if the algorithm is reliable, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmReliable(CryptographicSuite cryptographicSuite, SignatureAlgorithm signatureAlgorithm) {
        if (cryptographicSuite == null) {
            return true;
        }
        return signatureAlgorithm != null && cryptographicSuite.getAcceptableSignatureAlgorithms().containsKey(signatureAlgorithm);
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
        return digestAlgorithm != null && cryptographicSuite.getAcceptableDigestAlgorithms().containsKey(digestAlgorithm);
    }

    /**
     * Checks if the {code keyLength} for {@link SignatureAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to check key length for
     * @param keyLength {@link String} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmWithKeySizeReliable(CryptographicSuite cryptographicSuite,
                                                                  SignatureAlgorithm signatureAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return isSignatureAlgorithmWithKeySizeReliable(cryptographicSuite, signatureAlgorithm, keySize);
    }

    /**
     * Checks if the {code keyLength} for {@link SignatureAlgorithm} is reliable (acceptable)
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to check key length for
     * @param keySize {@link Integer} the key length to be checked
     * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmWithKeySizeReliable(CryptographicSuite cryptographicSuite,
                                                                  SignatureAlgorithm signatureAlgorithm, Integer keySize) {
        if (cryptographicSuite == null) {
            return true;
        }

        if (signatureAlgorithm != null && keySize != null) {
            Map<SignatureAlgorithm, Set<CryptographicSuiteEvaluation>> acceptableSignatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();
            if (!acceptableSignatureAlgorithms.containsKey(signatureAlgorithm)) {
                return false;
            }

            Set<CryptographicSuiteEvaluation> evaluations = acceptableSignatureAlgorithms.get(signatureAlgorithm);
            if (Utils.isCollectionNotEmpty(evaluations)) {
                for (CryptographicSuiteEvaluation evaluation : evaluations) {
                    if (isEvaluationApplicable(signatureAlgorithm.getEncryptionAlgorithm(), keySize, evaluation)) {
                        return true;
                    }
                }

            } else {
                // no evaluations -> return true
                return true;
            }
        }
        return false;
    }

    private static int parseKeySize(String keyLength) {
        return Utils.isStringDigits(keyLength) ? Integer.parseInt(keyLength) : 0;
    }

    /**
     * This method verifies whether the given {@code keyLength} of the {@code signatureAlgorithm} is big enough.
     * NOTE: This method only ensures that the key length is bigger than the minimal accepted key size.
     *       It does not consider the maximum requirements.
     *
     * @param cryptographicSuite {@link CryptographicSuite} set of validation constraints
     * @param signatureAlgorithm {@link SignatureAlgorithm} to be checked
     * @param keyLength {@link String}
     * @return TRUE if the signature algorithm key length is big enough, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmKeyLengthBigEnough(CryptographicSuite cryptographicSuite,
                                                                 SignatureAlgorithm signatureAlgorithm, String keyLength) {
        if (cryptographicSuite == null) {
            return false;
        }

        int keySize = parseKeySize(keyLength);
        if (signatureAlgorithm != null) {
            Map<SignatureAlgorithm, Set<CryptographicSuiteEvaluation>> acceptableSignatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();
            if (!acceptableSignatureAlgorithms.containsKey(signatureAlgorithm)) {
                return false;
            }

            Set<CryptographicSuiteEvaluation> evaluations = acceptableSignatureAlgorithms.get(signatureAlgorithm);
            if (Utils.isCollectionNotEmpty(evaluations)) {
                for (CryptographicSuiteEvaluation evaluation : evaluations) {
                    List<CryptographicSuiteParameter> parameterList = evaluation.getParameterList();
                    if (parameterList != null && Utils.isCollectionNotEmpty(parameterList)) {
                        for (CryptographicSuiteParameter parameter : parameterList) {
                            if (isSupported(signatureAlgorithm.getEncryptionAlgorithm(), parameter)) {
                                Integer parameterMin = parameter.getMin();
                                if (parameterMin == null || parameterMin < keySize) {
                                    return true;
                                }
                            }
                        }
                    }
                }

            }
        }
        return false;
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code signatureAlgorithm} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to get expiration date for
     * @param keyLength {@link String} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite,
                                         SignatureAlgorithm signatureAlgorithm, String keyLength) {
        int keySize = parseKeySize(keyLength);
        return getExpirationDate(cryptographicSuite, signatureAlgorithm, keySize);
    }

    /**
     * Gets an expiration date for the encryption algorithm with name {@code signatureAlgorithm} and {@code keyLength}.
     * Returns null if the expiration date is not defined for the algorithm.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param signatureAlgorithm {@link SignatureAlgorithm} to get expiration date for
     * @param keySize {@link Integer} key length used to sign the token
     * @return {@link Date}
     */
    public static Date getExpirationDate(CryptographicSuite cryptographicSuite,
                                         SignatureAlgorithm signatureAlgorithm, Integer keySize) {
        if (cryptographicSuite == null) {
            return null;
        }

        Date expirationDate = null;
        if (signatureAlgorithm != null && keySize != null) {
            Map<SignatureAlgorithm, Set<CryptographicSuiteEvaluation>> acceptableSignatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();
            Set<CryptographicSuiteEvaluation> evaluations = acceptableSignatureAlgorithms.get(signatureAlgorithm);
            if (Utils.isCollectionNotEmpty(evaluations)) {
                for (CryptographicSuiteEvaluation evaluation : evaluations) {
                    if (isEvaluationApplicable(signatureAlgorithm.getEncryptionAlgorithm(), keySize, evaluation)) {
                        // return the last expiration date (at least one evaluation shall match)
                        Date validityEnd = evaluation.getValidityEnd();
                        if (validityEnd == null) {
                            return null;
                        }
                        if (expirationDate == null || validityEnd.after(expirationDate)) {
                            expirationDate = validityEnd;
                        }
                    }
                }
            }
        }
        return expirationDate;
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
        if (cryptographicSuite == null) {
            return null;
        }

        Date expirationDate = null;
        if (digestAlgorithm != null) {
            Map<DigestAlgorithm, Set<CryptographicSuiteEvaluation>> acceptableDigestAlgorithms = cryptographicSuite.getAcceptableDigestAlgorithms();
            Set<CryptographicSuiteEvaluation> evaluations = acceptableDigestAlgorithms.get(digestAlgorithm);
            if (Utils.isCollectionNotEmpty(evaluations)) {
                for (CryptographicSuiteEvaluation evaluation : evaluations) {
                    // return the last expiration date (at least one evaluation shall match)
                    Date validityEnd = evaluation.getValidityEnd();
                    if (validityEnd == null) {
                        return null;
                    }
                    if (expirationDate == null || validityEnd.after(expirationDate)) {
                        expirationDate = validityEnd;
                    }
                }
            }
        }
        return expirationDate;
    }

    /**
     * This method verifies whether the {@code digestAlgorithm} is reliable at the {@code validationTime}
     *
     * @param cryptographicSuite {@link CryptographicSuite} containing the algorithm validation rules
     * @param digestAlgorithm {@link DigestAlgorithm} to be checked
     * @param validationTime {@link Date} validation time to check at
     * @return TRUE if the algorithm is reliable at the given time, FALSE otherwise
     */
    public static boolean isDigestAlgorithmReliableAtTime(CryptographicSuite cryptographicSuite, DigestAlgorithm digestAlgorithm,
                                                          Date validationTime) {
        Set<CryptographicSuiteEvaluation> evaluations = cryptographicSuite.getAcceptableDigestAlgorithms().get(digestAlgorithm);
        return reliableEvaluationExistsAtTime(evaluations, validationTime);
    }

    /**
     * This method returns a list of reliable {@code DigestAlgorithm} according to the current validation policy
     * at the given validation time
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param validationTime {@link Date} to verify against
     * @return a set of {@link DigestAlgorithm}s
     */
    public static Set<DigestAlgorithm> getReliableDigestAlgorithmsAtTime(CryptographicSuite cryptographicSuite, Date validationTime) {
        final Set<DigestAlgorithm> reliableDigestAlgorithms = new HashSet<>();
        for (Map.Entry<DigestAlgorithm, Set<CryptographicSuiteEvaluation>> entry : cryptographicSuite.getAcceptableDigestAlgorithms().entrySet()) {
            Set<CryptographicSuiteEvaluation> evaluations = entry.getValue();
            if (reliableEvaluationExistsAtTime(evaluations, validationTime)) {
                reliableDigestAlgorithms.add(entry.getKey());
            }
        }
        return reliableDigestAlgorithms;
    }

    private static boolean reliableEvaluationExistsAtTime(Collection<CryptographicSuiteEvaluation> evaluations, Date validationTime) {
        return reliableEvaluationExistsAtTime(null, null, evaluations, validationTime);
    }

    private static boolean reliableEvaluationExistsAtTime(EncryptionAlgorithm encryptionAlgorithm, Integer keySize,
                                                          Collection<CryptographicSuiteEvaluation> evaluations, Date validationTime) {
        if (Utils.isCollectionNotEmpty(evaluations)) {
            for (CryptographicSuiteEvaluation evaluation : evaluations) {
                if (encryptionAlgorithm == null || isEvaluationApplicable(encryptionAlgorithm, keySize, evaluation)) {
                    Date validityStart = evaluation.getValidityStart();
                    Date validityEnd = evaluation.getValidityEnd();
                    if ((validityStart == null || validityStart.before(validationTime))
                            && (validityEnd == null || validityEnd.after(validationTime))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * This method returns a list of reliable {@code SignatureAlgorithmWithMinKeySize} according to
     * the current validation policy and at the given time.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param validationTime {@link Date} to verify against
     * @return a set of {@link SignatureAlgorithmWithMinKeySize}s
     */
    public static Set<SignatureAlgorithmWithMinKeySize> getReliableSignatureAlgorithmsWithMinimalKeyLengthAtTime(
            CryptographicSuite cryptographicSuite, Date validationTime) {
        final Set<SignatureAlgorithmWithMinKeySize> result = new HashSet<>();
        for (Map.Entry<SignatureAlgorithm, Set<CryptographicSuiteEvaluation>> entry : cryptographicSuite.getAcceptableSignatureAlgorithms().entrySet()) {
            SignatureAlgorithm signatureAlgorithm = entry.getKey();
            Set<CryptographicSuiteEvaluation> evaluations = entry.getValue();

            Integer minKeyLength = null;
            if (Utils.isCollectionNotEmpty(evaluations)) {
                for (CryptographicSuiteEvaluation evaluation : evaluations) {
                    if (isEvaluationApplicable(signatureAlgorithm.getEncryptionAlgorithm(), null, evaluation)) {
                        Date validityStart = evaluation.getValidityStart();
                        Date validityEnd = evaluation.getValidityEnd();
                        if ((validityStart == null || validityStart.before(validationTime))
                                && (validityEnd == null || validityEnd.after(validationTime))) {
                            int keyLength = getMinKeyLength(signatureAlgorithm.getEncryptionAlgorithm(), evaluation);
                            if (minKeyLength == null || minKeyLength > keyLength) {
                                minKeyLength = keyLength;
                            }
                        }
                    }
                }
            }
            if (minKeyLength != null) {
                result.add(new SignatureAlgorithmWithMinKeySize(signatureAlgorithm, minKeyLength));
            }
        }
        return result;
    }

    /**
     * This method verifies whether the {@code signatureAlgorithm} with the {@code keySize} is reliable at the {@code validationTime}
     *
     * @param cryptographicSuite {@link CryptographicSuite} containing the algorithm validation rules
     * @param signatureAlgorithm {@link SignatureAlgorithm} to be checked
     * @param keyLength {@link String} used to create the signature
     * @param validationTime {@link Date} validation time to check at
     * @return TRUE if the algorithm is reliable at the given time, FALSE otherwise
     */
    public static boolean isSignatureAlgorithmReliableAtTime(CryptographicSuite cryptographicSuite, SignatureAlgorithm signatureAlgorithm,
                                                             String keyLength, Date validationTime) {
        // An unidentified signature algorithm (null) is not reliable. Without this check
        // the validation ends with a NullPointerException when AcceptableEncryptionAlgo and MiniPublicKeySize
        // are below FAIL (the check chain continues up to SignatureAlgorithmAtValidationTimeCheck).
        if (signatureAlgorithm == null) {
            return false;
        }
        Set<CryptographicSuiteEvaluation> evaluations = cryptographicSuite.getAcceptableSignatureAlgorithms().get(signatureAlgorithm);
        return reliableEvaluationExistsAtTime(signatureAlgorithm.getEncryptionAlgorithm(), parseKeySize(keyLength), evaluations, validationTime);
    }

    private static boolean isEvaluationApplicable(EncryptionAlgorithm algorithm, Integer keySize, CryptographicSuiteEvaluation evaluation) {
        List<CryptographicSuiteParameter> parameterList = evaluation.getParameterList();
        if (parameterList == null || parameterList.isEmpty()) {
            return true;
        }
        for (CryptographicSuiteParameter parameter : parameterList) {
            if (!isSupported(algorithm, parameter)) {
                continue;
            }
            if (keySize != null && ((parameter.getMin() != null && keySize < parameter.getMin())
                    || (parameter.getMax() != null && keySize > parameter.getMax()))) {
                continue;
            }
            return true;
        }
        return false;
    }

    private static int getMinKeyLength(EncryptionAlgorithm algorithm, CryptographicSuiteEvaluation evaluation) {
        Integer minKeyLength = null;
        List<CryptographicSuiteParameter> parameterList = evaluation.getParameterList();
        if (parameterList != null && !parameterList.isEmpty()) {
            for (CryptographicSuiteParameter parameter : parameterList) {
                if (!isSupported(algorithm, parameter)) {
                    continue;
                }
                if (parameter.getMin() == null) {
                    return 0;
                }
                if (minKeyLength == null || minKeyLength > parameter.getMin()) {
                    minKeyLength = parameter.getMin();
                }
            }
        }
        return minKeyLength != null ? minKeyLength : 0;
    }

    private static boolean isSupported(EncryptionAlgorithm encryptionAlgorithm, CryptographicSuiteParameter parameter) {
        String parameterName = parameter.getName();
        // first come, first served logic
        if (MODULES_LENGTH_PARAMETER.equals(parameterName)) {
            if (EncryptionAlgorithm.RSA.isEquivalent(encryptionAlgorithm)) {
                return true;
            }

        } else if (PLENGTH_PARAMETER.equals(parameterName)) {
            if (EncryptionAlgorithm.DSA.isEquivalent(encryptionAlgorithm) ||
                    EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm) ||
                    EncryptionAlgorithm.EDDSA.isEquivalent(encryptionAlgorithm)) {
                return true;
            }

        } else if (QLENGTH_PARAMETER.equals(parameterName)) {
            // process silently (not supported)

        } else {
            LOG.debug("Unknown Algorithms Parameter type '{}'!", parameterName);
        }
        return false;
    }

}
