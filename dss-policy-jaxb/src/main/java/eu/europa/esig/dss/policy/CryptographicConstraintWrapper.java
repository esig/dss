package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
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
import java.util.TimeZone;

/**
 * Wraps a {@code CryptographicConstraint} of the DSS JAXB validation policy implementation
 * into a {@code CryptographicConstraintWrapper}
 *
 */
public class CryptographicConstraintWrapper extends LevelConstraintWrapper implements CryptographicSuite {

    private static final Logger LOG = LoggerFactory.getLogger(CryptographicConstraintWrapper.class);

    /** The default date format */
    private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

    /** The default timezone (UTC) */
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

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
    public String getPolicyName() {
        return "DSS Cryptographic Constraint";
    }

    @Override
    public List<DigestAlgorithm> getAcceptableDigestAlgorithms() {
        if (acceptableDigestAlgorithms == null) {
            acceptableDigestAlgorithms = new ArrayList<>();
            if (constraint != null) {
                ListAlgo acceptableDigestAlgos = ((CryptographicConstraint) constraint).getAcceptableDigestAlgo();
                if (acceptableDigestAlgos != null) {
                    for (Algo algo : acceptableDigestAlgos.getAlgos()) {
                        DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                        if (digestAlgorithm != null) {
                            acceptableDigestAlgorithms.add(digestAlgorithm);
                        }
                    }
                }
            }
        }
        return acceptableDigestAlgorithms;
    }

    @Override
    public List<EncryptionAlgorithm> getAcceptableEncryptionAlgorithms() {
        if (acceptableEncryptionAlgorithms == null) {
            acceptableEncryptionAlgorithms = new ArrayList<>();
            if (constraint != null) {
                ListAlgo acceptableEncryptionAlgos = ((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo();
                if (acceptableEncryptionAlgos != null) {
                    for (Algo algo : acceptableEncryptionAlgos.getAlgos()) {
                        EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                        if (encryptionAlgorithm != null) {
                            acceptableEncryptionAlgorithms.add(encryptionAlgorithm);
                        }
                    }
                }
            }
        }
        return acceptableEncryptionAlgorithms;
    }

    @Override
    public List<EncryptionAlgorithmWithMinKeySize> getAcceptableEncryptionAlgorithmsWithMinKeySizes() {
        if (acceptableEncryptionAlgorithmsWithMinKeySizes == null) {
            acceptableEncryptionAlgorithmsWithMinKeySizes = new ArrayList<>();
            if (constraint != null) {
                ListAlgo miniPublicKeySizes = ((CryptographicConstraint) constraint).getMiniPublicKeySize();
                if (miniPublicKeySizes != null) {
                    for (Algo algo : miniPublicKeySizes.getAlgos()) {
                        EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                        if (encryptionAlgorithm != null) {
                            acceptableEncryptionAlgorithmsWithMinKeySizes.add(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()));
                        }
                    }
                }
            }
        }
        return acceptableEncryptionAlgorithmsWithMinKeySizes;
    }

    @Override
    public Map<DigestAlgorithm, Date> getAcceptableDigestAlgorithmsWithExpirationDates() {
        if (acceptableDigestAlgorithmsWithExpirationDates == null) {
            acceptableDigestAlgorithmsWithExpirationDates = new LinkedHashMap<>();
            if (constraint != null) {
                AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
                if (algoExpirationDates != null) {
                    SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                    for (Algo algo: algoExpirationDates.getAlgos()) {
                        final DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algo.getValue());
                        if (digestAlgorithm != null) {
                            Date expirationDate = getDate(algo, dateFormat);
                            acceptableDigestAlgorithmsWithExpirationDates.put(digestAlgorithm, expirationDate);
                        }
                    }
                }
            }
        }
        return acceptableDigestAlgorithmsWithExpirationDates;
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
        SimpleDateFormat sdf = new SimpleDateFormat(expirations.getFormat() != null ? expirations.getFormat() : DEFAULT_DATE_FORMAT);
        sdf.setTimeZone(UTC);
        return sdf;
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
        if (acceptableEncryptionAlgorithmsWithExpirationDates == null) {
            acceptableEncryptionAlgorithmsWithExpirationDates = new LinkedHashMap<>();
            if (constraint != null) {
                AlgoExpirationDate algoExpirationDates = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
                if (algoExpirationDates != null) {
                    SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
                    for (Algo algo: algoExpirationDates.getAlgos()) {
                        final EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algo.getValue());
                        if (encryptionAlgorithm != null) {
                            Date expirationDate = getDate(algo, dateFormat);
                            acceptableEncryptionAlgorithmsWithExpirationDates.put(new EncryptionAlgorithmWithMinKeySize(encryptionAlgorithm, algo.getSize()), expirationDate);
                        }
                    }
                }
            }
        }
        return acceptableEncryptionAlgorithmsWithExpirationDates;
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
    public void setLevel(Level level) {
        if (constraint != null) {
            constraint.setLevel(level);
        }
    }

    @Override
    public Level getAcceptableEncryptionAlgorithmsLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo());
        }
        return null;
    }

    @Override
    public void setAcceptableEncryptionAlgorithmsLevel(Level acceptableEncryptionAlgorithmsLevel) {
        if (constraint != null) {
            ListAlgo acceptableEncryptionAlgo = ((CryptographicConstraint) constraint).getAcceptableEncryptionAlgo();
            if (acceptableEncryptionAlgo != null) {
                acceptableEncryptionAlgo.setLevel(acceptableEncryptionAlgorithmsLevel);
            }
        }
    }

    @Override
    public Level getAcceptableEncryptionAlgorithmsMiniKeySizeLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getMiniPublicKeySize());
        }
        return null;
    }

    @Override
    public void setAcceptableEncryptionAlgorithmsMiniKeySizeLevel(Level acceptableEncryptionAlgorithmsMiniKeySizeLevel) {
        if (constraint != null) {
            ListAlgo miniPublicKeySize = ((CryptographicConstraint) constraint).getMiniPublicKeySize();
            if (miniPublicKeySize != null) {
                miniPublicKeySize.setLevel(acceptableEncryptionAlgorithmsMiniKeySizeLevel);
            }
        }
    }

    @Override
    public Level getAcceptableDigestAlgorithmsLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getAcceptableDigestAlgo());
        }
        return null;
    }

    @Override
    public void setAcceptableDigestAlgorithmsLevel(Level acceptableDigestAlgorithmsLevel) {
        if (constraint != null) {
            ListAlgo acceptableDigestAlgo = ((CryptographicConstraint) constraint).getAcceptableDigestAlgo();
            if (acceptableDigestAlgo != null) {
                acceptableDigestAlgo.setLevel(acceptableDigestAlgorithmsLevel);
            }
        }
    }

    @Override
    public Level getAlgorithmsExpirationDateLevel() {
        if (constraint != null) {
            return getCryptographicLevel(((CryptographicConstraint) constraint).getAlgoExpirationDate());
        }
        return null;
    }

    @Override
    public void setAlgorithmsExpirationDateLevel(Level algorithmsExpirationDateLevel) {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null) {
                algoExpirationDate.setLevel(algorithmsExpirationDateLevel);
            }
        }
    }

    @Override
    public Level getAlgorithmsExpirationDateAfterUpdateLevel() {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null && algoExpirationDate.getLevelAfterUpdate() != null) {
                return algoExpirationDate.getLevelAfterUpdate();
            }
            return getCryptographicLevel(algoExpirationDate);
        }
        return null;
    }

    @Override
    public void setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level algorithmsExpirationTimeAfterPolicyUpdateLevel) {
        if (constraint != null) {
            AlgoExpirationDate algoExpirationDate = ((CryptographicConstraint) constraint).getAlgoExpirationDate();
            if (algoExpirationDate != null) {
                algoExpirationDate.setLevelAfterUpdate(algorithmsExpirationTimeAfterPolicyUpdateLevel);
            }
        }
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

    private Level getCryptographicLevel(LevelConstraint cryptoConstraint) {
        if (cryptoConstraint != null && cryptoConstraint.getLevel() != null) {
            return cryptoConstraint.getLevel();
        }
        // return global Level if target level is not present
        return getLevel();
    }

}
