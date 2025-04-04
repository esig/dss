package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Contains policy for validation of cryptographic suites used on the signature or certificates
 *
 */
public interface CryptographicSuite extends LevelRule {

    /**
     * Gets a list of digest algorithms accepted by the validation policy
     *
     * @return a list of {@link DigestAlgorithm}s
     */
    List<DigestAlgorithm> getAcceptableDigestAlgorithms();

    /**
     * Gets a list of encryption algorithms accepted by the validation policy
     *
     * @return a list of {@link EncryptionAlgorithm}s
     */
    List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms();

    /**
     * Gets a list of encryption algorithms together with their minimum used key sizes accepted by the validation policy
     *
     * @return a list of {@link EncryptionAlgorithmWithMinKeySize}s
     */
    List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes();

    /**
     * Gets a map of supported digest algorithms with the corresponding expiration dates
     *
     * @return a map between {@code DigestAlgorithm}s and expiration {@code Date}s
     */
    Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates();

    /**
     * Gets a map of supported encryption algorithms with the applicable key sizes with the corresponding expiration dates
     *
     * @return a map between {@code EncryptionAlgorithmWithMinKeySize}s and expiration {@code Date}s
     */
    Map<EncryptionAlgorithmWithMinKeySize, Date> getAcceptableEncryptionAlgorithmsWithExpirationDates();

    /**
     * Returns a level constraint for AcceptableEncryptionAlgo constraint if present,
     * the global {@code getLevel} otherwise.
     *
     * @return {@link LevelRule}
     */
    LevelRule getAcceptableEncryptionAlgoLevel();

    /**
     * Returns a level constraint for MiniPublicKeySize constraint if present,
     * the global {@code getLevel} otherwise.
     *
     * @return {@link LevelRule}
     */
    LevelRule getMiniPublicKeySizeLevel();

    /**
     * Returns a level constraint for AcceptableDigestAlgo constraint if present,
     * the global {@code getLevel} otherwise.
     *
     * @return {@link LevelRule}
     */
    LevelRule getAcceptableDigestAlgoLevel();

    /**
     * Returns a level constraint for AlgoExpirationDate constraint if present,
     * the global {@code getLevel} otherwise.
     *
     * @return {@link LevelRule}
     */
    LevelRule getAlgoExpirationDateLevel();

    /**
     * Returns a date of the update of the cryptographic suites within the validation policy
     *
     * @return {@link Date}
     */
    Date getCryptographicSuiteUpdateDate();

    /**
     * Returns a level constraint for AlgoExpirationDate constraint if present,
     * the global {@code getLevel} otherwise.
     *
     * @return {@link Level}
     */
    Level getAlgoExpirationDateAfterUpdateLevel();

}
