package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps a {@code CryptographicConstraint} of the DSS JAXB validation policy implementation
 * into a {@code CryptographicConstraintWrapper}
 *
 */
public class CryptographicConstraintWrapper extends LevelConstraintWrapper implements CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicConstraintWrapper.class);

    /** The default date format */
    private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

    /**
     * Constructor to create an empty instance of Cryptographic constraints
     */
    public CryptographicConstraintWrapper() {
        super(null);
    }

    /**
     * Default constructor
     *
     * @param constraint {@link CryptographicConstraint}
     */
    public CryptographicConstraintWrapper(CryptographicConstraint constraint) {
        super(constraint);
    }

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        final List<DigestAlgorithm> digestAlgorithms = new ArrayList<>();
        if (constraint != null) {
            ListAlgo acceptableDigestAlgos = ((CryptographicConstraint) constraint).getAcceptableDigestAlgo();
            if (acceptableDigestAlgos != null) {
                for (Algo algo : acceptableDigestAlgos.getAlgos()) {
                    DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                    if (digestAlgorithm != null) {
                        digestAlgorithms.add(digestAlgorithm);
                    }
                }
            }
        }
        return digestAlgorithms;
    }

    @Override
    public List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms() {
        final List<EncryptionAlgorithm> encryptionAlgorithms = new ArrayList<>();
        if (constraint != null) {
            ListAlgo acceptableEncryptionAlgos = ((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo();
            if (acceptableEncryptionAlgos != null) {
                for (Algo algo : acceptableEncryptionAlgos.getAlgos()) {
                    EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                    if (encryptionAlgorithm != null) {
                        encryptionAlgorithms.add(encryptionAlgorithm);
                    }
                }
            }
        }
        return encryptionAlgorithms;
    }

    @Override
    public List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes() {
        final List<EncryptionAlgorithmWithMinKeySize> encryptionAlgorithms = new ArrayList<>();
        if (constraint != null) {
            ListAlgo miniPublicKeySizes = ((CryptographicConstraint) constraint).getMiniPublicKeySize();
            if (miniPublicKeySizes != null) {
                for (Algo algo : miniPublicKeySizes.getAlgos()) {
                    EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                    if (encryptionAlgorithm != null) {
                        encryptionAlgorithms.add(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()));
                    }
                }
            }
        }
        return encryptionAlgorithms;
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        final Map<DigestAlgorithm, Date> digestAlgorithmsMap = new LinkedHashMap<>();
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDates != null) {
                SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                for (Algo algo: algoExpirationDates.getAlgos()) {
                    final DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                    if (digestAlgorithm != null) {
                        Date expirationDate = getDate(algo, dateFormat);
                        digestAlgorithmsMap.put(digestAlgorithm, expirationDate);
                    }
                }
            }
        }
        return digestAlgorithmsMap;
    }

    private DigestAlgorithm toDigestAlgorithm(String algorithmName) {
        try {
            return DigestAlgorithm.forName(algorithmName);
        } catch (IllegalArgumentException e) {
            // continue silently
            return null;
        }
    }

    private SimpleDateFormat getUsedDateFormat(AlgoExpirationDate expirations) {
        return new SimpleDateFormat(expirations.getFormat() != null ? expirations.getFormat() : DEFAULT_DATE_FORMAT);
    }

    private Date getDate(Algo algo, SimpleDateFormat format) {
        if (algo != null) {
            return getDate(algo.getDate(), format);
        }
        return null;
    }

    private Date getDate(String dateString, SimpleDateFormat format) {
        if (dateString != null) {
            try {
                return format.parse(dateString);
            } catch (ParseException e) {
                LOG.warn("Unable to parse '{}' with format '{}'", dateString, format);
            }
        }
        return null;
    }

    @Override
    public Map<EncryptionAlgorithmWithMinKeySize, Date> getAcceptableEncryptionAlgorithmsWithExpirationDates() {
        final Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsMap = new LinkedHashMap<>();
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDates != null) {
                SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                for (Algo algo: algoExpirationDates.getAlgos()) {
                    final EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                    if (encryptionAlgorithm != null) {
                        Date expirationDate = getDate(algo, dateFormat);
                        encryptionAlgorithmsMap.put(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()), expirationDate);
                    }
                }
            }
        }
        return encryptionAlgorithmsMap;
    }

    private EncryptionAlgorithm toEncryptionAlgorithm(String algorithmName) {
        try {
            return EncryptionAlgorithm.forName(algorithmName);
        } catch (IllegalArgumentException e) {
            // continue silently
            return null;
        }
    }

    @Override
    public LevelRule getAcceptableEncryptionAlgoLevel() {
        if (constraint != null) {
            return getCryptographicLevelRule(((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo());
        }
        return null;
    }

    @Override
    public LevelRule getMiniPublicKeySizeLevel() {
        if (constraint != null) {
            return getCryptographicLevelRule(((CryptographicConstraint) constraint).getMiniPublicKeySize());
        }
        return null;
    }

    @Override
    public LevelRule getAcceptableDigestAlgoLevel() {
        if (constraint != null) {
            return getCryptographicLevelRule(((CryptographicConstraint) constraint).getAcceptableDigestAlgo());
        }
        return null;
    }

    @Override
    public LevelRule getAlgoExpirationDateLevel() {
        if (constraint != null) {
            return getCryptographicLevelRule(((CryptographicConstraint) constraint).getAlgoExpirationDate());
        }
        return null;
    }

    private LevelRule getCryptographicLevelRule(LevelConstraint cryptoConstraint) {
        if (cryptoConstraint != null && cryptoConstraint.getLevel() != null) {
            return new LevelConstraintWrapper(cryptoConstraint);
        }
        // return global LevelRule if target level is not present
        return this;
    }

    @Override
    public Date getCryptographicSuiteUpdateDate() {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDates != null) {
                final SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                return getDate(algoExpirationDates.getUpdateDate(), dateFormat);
            }
        }
        return null;
    }

    @Override
    public Level getAlgoExpirationDateAfterUpdateLevel() {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null && algoExpirationDate.getLevelAfterUpdate() != null) {
                return algoExpirationDate.getLevelAfterUpdate();
            }
            LevelRule LevelRule = getCryptographicLevelRule(algoExpirationDate);
            return LevelRule != null ? LevelRule.getLevel() : null;
        }
        return null;
    }

}
