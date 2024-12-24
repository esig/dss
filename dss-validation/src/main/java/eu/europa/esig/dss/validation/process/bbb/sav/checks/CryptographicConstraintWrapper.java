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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * The wrapper for cryptographic information retrieved from a validation policy
 *
 */
public class CryptographicConstraintWrapper {

	private static final Logger LOG = LoggerFactory.getLogger(CryptographicConstraintWrapper.class);

	/** The default date format */
	private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	/** The cryptographic constraint */
	private final CryptographicConstraint constraint;

	/**
	 * Default constructor
	 *
	 * @param constraint {@link CryptographicConstraint}
	 */
	public CryptographicConstraintWrapper(CryptographicConstraint constraint) {
		this.constraint = constraint;
	}

	/**
	 * Checks if the given {@link EncryptionAlgorithm} is reliable (acceptable)
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check
	 * @return TRUE if the algorithm is reliable, FALSE otherwise
	 */
	public boolean isEncryptionAlgorithmReliable(EncryptionAlgorithm encryptionAlgorithm) {
		if (encryptionAlgorithm != null && constraint != null) {
			ListAlgo acceptableEncryptionAlgos = constraint.getAcceptableEncryptionAlgo();
			Algo algo = getMatchingAlgo(acceptableEncryptionAlgos, encryptionAlgorithm);
			return algo != null;
		}
		return false;
	}

	/**
	 * Checks if the given {@link DigestAlgorithm} is reliable (acceptable)
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to check
	 * @return TRUE if the algorithm is reliable, FALSE otherwise
	 */
	public boolean isDigestAlgorithmReliable(DigestAlgorithm digestAlgorithm) {
		if (digestAlgorithm != null && constraint != null) {
			ListAlgo acceptableDigestAlgos = constraint.getAcceptableDigestAlgo();
			Algo algo = getMatchingAlgo(acceptableDigestAlgos, digestAlgorithm);
			return algo != null;
		}
		return false;
	}

	/**
	 * Checks if the {code keyLength} for {@link EncryptionAlgorithm} is reliable (acceptable)
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check key length for
	 * @param keyLength {@link String} the key length to be checked
	 * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
	 */
	public boolean isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
		int keySize = parseKeySize(keyLength);
		return isEncryptionAlgorithmWithKeySizeReliable(encryptionAlgorithm, keySize);
	}

	/**
	 * Checks if the {code keyLength} for {@link EncryptionAlgorithm} is reliable (acceptable)
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check key length for
	 * @param keySize {@link Integer} the key length to be checked
	 * @return TRUE if the key length for the algorithm is reliable, FALSE otherwise
	 */
	public boolean isEncryptionAlgorithmWithKeySizeReliable(EncryptionAlgorithm encryptionAlgorithm, Integer keySize) {
		if (encryptionAlgorithm != null && keySize != 0 && constraint != null) {
			Integer size = getAlgoKeySizeFromConstraint(encryptionAlgorithm);
            return size == null || size <= keySize;
		}
		return false;
	}

	private Integer getAlgoKeySizeFromConstraint(EncryptionAlgorithm encryptionAlgorithm) {
		if (constraint != null) {
			ListAlgo miniPublicKeySizeEncryptionAlgos = constraint.getMiniPublicKeySize();
			Algo algo = getMatchingAlgo(miniPublicKeySizeEncryptionAlgos, encryptionAlgorithm);
			if (algo != null) {
				return algo.getSize();
			}
		}
		return null;
	}

	/**
	 * Gets an expiration date for the encryption algorithm with name {@code algoToSearch} and {@code keyLength}.
	 * Returns null if the expiration date is not defined for the algorithm.
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to get expiration date for
	 * @param keyLength {@link String} key length used to sign the token
	 * @return {@link Date}
	 */
	public Date getExpirationDate(EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
		int keySize = parseKeySize(keyLength);
		return getExpirationDate(encryptionAlgorithm, keySize);
	}

	/**
	 * Gets an expiration date for the encryption algorithm with name {@code algoToSearch} and {@code keyLength}.
	 * Returns null if the expiration date is not defined for the algorithm.
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to get expiration date for
	 * @param keySize {@link Integer} key length used to sign the token
	 * @return {@link Date}
	 */
	public Date getExpirationDate(EncryptionAlgorithm encryptionAlgorithm, Integer keySize) {
		TreeMap<Integer, Date> dates = new TreeMap<>();
		AlgoExpirationDate algoExpirationDates = getAlgoExpirationDates();
		if (algoExpirationDates != null) {
			List<Algo> matchingAlgos = getMatchingAlgos(algoExpirationDates, encryptionAlgorithm);
			if (Utils.isCollectionNotEmpty(matchingAlgos)) {
				SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
				for (Algo algo : matchingAlgos) {
					dates.put(algo.getSize(), getDate(algo, dateFormat));
				}
			}
		}

		Entry<Integer, Date> floorEntry = dates.floorEntry(keySize);
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
	 * @param digestAlgorithm {@link DigestAlgorithm} the algorithm to get expiration date for
	 * @return {@link Date}
	 */
	public Date getExpirationDate(DigestAlgorithm digestAlgorithm) {
		AlgoExpirationDate algoExpirationDates = getAlgoExpirationDates();
		if (algoExpirationDates != null && digestAlgorithm != null) {
			List<Algo> matchingAlgos = getMatchingAlgos(algoExpirationDates, digestAlgorithm);
			if (Utils.collectionSize(matchingAlgos) == 0) {
				return null;
			} else if (Utils.collectionSize(matchingAlgos) == 1) {
				SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
				return getDate(matchingAlgos.iterator().next(), dateFormat);
			} else {
				throw new IllegalArgumentException(String.format(
						"Multiple expiration constraints are provided for the same digest algorithm '%s'!", digestAlgorithm.getName()));
			}
		}
		return null;
	}

	private int parseKeySize(String keyLength) {
		return Utils.isStringDigits(keyLength) ? Integer.parseInt(keyLength) : 0;
	}

	private AlgoExpirationDate getAlgoExpirationDates() {
		if (constraint != null) {
			return constraint.getAlgoExpirationDate();
		}
		return null;
	}

	private SimpleDateFormat getUsedDateFormat(AlgoExpirationDate expirations) {
		return new SimpleDateFormat(Utils.isStringEmpty(expirations.getFormat()) ?
				DEFAULT_DATE_FORMAT : expirations.getFormat());
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

	/**
	 * This method returns a list of reliable {@code DigestAlgorithm} according to the current validation policy
	 * at the given validation time
	 *
	 * @param validationTime {@link Date} to verify against
	 * @return a list of {@link DigestAlgorithm}s
	 */
	public List<DigestAlgorithm> getReliableDigestAlgorithmsAtTime(Date validationTime) {
		List<DigestAlgorithm> reliableDigestAlgorithms = new ArrayList<>();
		if (constraint != null) {
			ListAlgo acceptableDigestAlgo = constraint.getAcceptableDigestAlgo();
			if (acceptableDigestAlgo != null) {
				List<String> acceptableDigestAlgorithmNames = acceptableDigestAlgo.getAlgos().stream()
						.map(Algo::getValue).collect(Collectors.toList());
				AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
				for (String algorithmName : acceptableDigestAlgorithmNames) {
					final DigestAlgorithm digestAlgorithm = toDigestAlgorithm(algorithmName);
					if (isReliableDigestAlgorithm(digestAlgorithm, algoExpirationDate, validationTime)) {
						reliableDigestAlgorithms.add(digestAlgorithm);
					}
				}
			}
		}
		return reliableDigestAlgorithms;
	}

	private DigestAlgorithm toDigestAlgorithm(String algorithmName) {
		try {
			return DigestAlgorithm.forName(algorithmName);
		} catch (IllegalArgumentException e) {
			LOG.warn("Unable to parse a DigestAlgorithm with name '{}'! Reason : {}", algorithmName, e.getMessage(), e);
			return null;
		}
	}

	private boolean isReliableDigestAlgorithm(DigestAlgorithm digestAlgorithm, AlgoExpirationDate algoExpirationDates, Date validationTime) {
		if (digestAlgorithm != null && algoExpirationDates != null) {
			for (Algo algo : algoExpirationDates.getAlgos()) {
				if (digestAlgorithm.getName().equals(algo.getValue())) {
					Date expirationDate = getExpirationDate(digestAlgorithm);
					return expirationDate == null || !getExpirationDate(digestAlgorithm).before(validationTime);
				}
			}
		}
		return true;
	}

	/**
	 * This method returns a map between reliable {@code EncryptionAlgorithm} according to the current validation policy
	 * and their minimal accepted key length at the given time.
	 *
	 * @param validationTime {@link Date} to verify against
	 * @return a map of {@link EncryptionAlgorithm}s or their minimal accepted key length
	 */
	public Map<EncryptionAlgorithm, Integer> getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(Date validationTime) {
		Map<EncryptionAlgorithm, Integer> reliableEncryptionAlgorithms = new EnumMap<>(EncryptionAlgorithm.class);
		if (constraint != null) {
			ListAlgo acceptableEncryptionAlgo = constraint.getAcceptableEncryptionAlgo();
			if (acceptableEncryptionAlgo != null) {
				List<String> acceptableEncryptionAlgorithmNames = acceptableEncryptionAlgo.getAlgos().stream()
						.map(Algo::getValue).collect(Collectors.toList());
				AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
				for (String algorithmName : acceptableEncryptionAlgorithmNames) {
					final EncryptionAlgorithm encryptionAlgorithm = toEncryptionAlgorithm(algorithmName);
					if (isReliableEncryptionAlgorithm(encryptionAlgorithm, algoExpirationDate, validationTime)) {
						Integer minReliableKeySize = getMinReliableKeySize(encryptionAlgorithm, algoExpirationDate, validationTime);
						reliableEncryptionAlgorithms.put(encryptionAlgorithm, minReliableKeySize);
					}
				}
			}
		}
		return reliableEncryptionAlgorithms;
	}

	private EncryptionAlgorithm toEncryptionAlgorithm(String algorithmName) {
		return EncryptionAlgorithm.forName(algorithmName);
	}

	private boolean isReliableEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm, AlgoExpirationDate algoExpirationDates, Date validationTime) {
		boolean algoFound = false;
		if (encryptionAlgorithm != null && algoExpirationDates != null) {
			for (Algo algo : algoExpirationDates.getAlgos()) {
				if (encryptionAlgorithm.getName().equals(algo.getValue())) {
					Date expirationDate = getExpirationDate(encryptionAlgorithm, algo.getSize());
					if (expirationDate == null || !expirationDate.before(validationTime)) {
						return true;
					}
					algoFound = algoFound || algo.getDate() != null;
				}
			}
		}
		return !algoFound;
	}

	private Integer getMinReliableKeySize(EncryptionAlgorithm encryptionAlgorithm, AlgoExpirationDate algoExpirationDates, Date validationTime) {
		Integer minimalAcceptedKeySize = null;
		if (encryptionAlgorithm != null && algoExpirationDates != null) {
			for (Algo algo : algoExpirationDates.getAlgos()) {
				if (encryptionAlgorithm.getName().equals(algo.getValue()) && (minimalAcceptedKeySize != null || algo.getDate() != null)) {
					Date expirationDate = getExpirationDate(encryptionAlgorithm, algo.getSize());
					if (isEncryptionAlgorithmWithKeySizeReliable(encryptionAlgorithm, algo.getSize()) &&
							(expirationDate == null || !expirationDate.before(validationTime)) &&
							(minimalAcceptedKeySize == null || algo.getSize() < minimalAcceptedKeySize)) {
							minimalAcceptedKeySize = algo.getSize();
					}
				}
			}
		}
		Integer minKeySizeLimit = getAlgoKeySizeFromConstraint(encryptionAlgorithm);
		if (minimalAcceptedKeySize == null || (minKeySizeLimit != null && minKeySizeLimit > minimalAcceptedKeySize)) {
			minimalAcceptedKeySize = minKeySizeLimit;
		}
		return minimalAcceptedKeySize;
	}

	private Algo getMatchingAlgo(ListAlgo listAlgo, EncryptionAlgorithm encryptionAlgorithm) {
		List<Algo> matchingAlgos = getMatchingAlgos(listAlgo, encryptionAlgorithm);
		if (Utils.isCollectionNotEmpty(matchingAlgos)) {
			return matchingAlgos.iterator().next(); // return first entry
		}
		return null;
	}

	private List<Algo> getMatchingAlgos(ListAlgo listAlgo, EncryptionAlgorithm encryptionAlgorithm) {
		final List<Algo> result = new ArrayList<>();
		if (listAlgo != null && encryptionAlgorithm != null) {
			for (Algo algo : listAlgo.getAlgos()) {
				if (algo.getValue().equals(encryptionAlgorithm.getName())) {
					result.add(algo);
				}
			}
		}
		return result;
	}

	private Algo getMatchingAlgo(ListAlgo listAlgo, DigestAlgorithm digestAlgorithm) {
		List<Algo> matchingAlgos = getMatchingAlgos(listAlgo, digestAlgorithm);
		if (Utils.isCollectionNotEmpty(matchingAlgos)) {
			return matchingAlgos.iterator().next(); // return first entry
		}
		return null;
	}

	private List<Algo> getMatchingAlgos(ListAlgo listAlgo, DigestAlgorithm digestAlgorithm) {
		final List<Algo> result = new ArrayList<>();
		if (listAlgo != null) {
			for (Algo algo : listAlgo.getAlgos()) {
				if (algo.getValue().equals(digestAlgorithm.getName())) {
					result.add(algo);
				}
			}
		}
		return result;
	}

	/**
	 * Returns the global validation level of the cryptographic constraints for the current token
	 *
	 * @return {@link Level}
	 */
	public Level getLevel() {
		if (constraint != null) {
			return constraint.getLevel();
		}
		return null;
	}

	/**
	 * Returns a level constraint for AcceptableEncryptionAlgo constraint if present,
	 * the global {@code getLevel} otherwise.
	 *
	 * @return {@link LevelConstraint}
	 */
	public LevelConstraint getAcceptableEncryptionAlgoLevel() {
		if (constraint != null) {
			return getCryptographicLevelConstraint(constraint.getAcceptableEncryptionAlgo());
		}
		return null;
	}

	/**
	 * Returns a level constraint for MiniPublicKeySize constraint if present,
	 * the global {@code getLevel} otherwise.
	 *
	 * @return {@link LevelConstraint}
	 */
	public LevelConstraint getMiniPublicKeySizeLevel() {
		if (constraint != null) {
			return getCryptographicLevelConstraint(constraint.getMiniPublicKeySize());
		}
		return null;
	}

	/**
	 * Returns a level constraint for AcceptableDigestAlgo constraint if present,
	 * the global {@code getLevel} otherwise.
	 *
	 * @return {@link LevelConstraint}
	 */
	public LevelConstraint getAcceptableDigestAlgoLevel() {
		if (constraint != null) {
			return getCryptographicLevelConstraint(constraint.getAcceptableDigestAlgo());
		}
		return null;
	}

	/**
	 * Returns a level constraint for AlgoExpirationDate constraint if present,
	 * the global {@code getLevel} otherwise.
	 *
	 * @return {@link LevelConstraint}
	 */
	public LevelConstraint getAlgoExpirationDateLevel() {
		if (constraint != null) {
			return getCryptographicLevelConstraint(constraint.getAlgoExpirationDate());
		}
		return null;
	}

	private LevelConstraint getCryptographicLevelConstraint(LevelConstraint cryptoConstraint) {
		if (cryptoConstraint != null && cryptoConstraint.getLevel() != null) {
			return cryptoConstraint;
		}
		// return global LevelConstraint if target level is not present
		return constraint;
	}

	/**
	 * Returns a date of the update of the cryptographic suites within the validation policy
	 *
	 * @return {@link Date}
	 */
	public Date getCryptographicSuiteUpdateDate() {
		AlgoExpirationDate algoExpirationDates = getAlgoExpirationDates();
		if (algoExpirationDates != null) {
			final SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
			return getDate(algoExpirationDates.getUpdateDate(), dateFormat);
		}
		return null;
	}

	/**
	 * Returns a level constraint for AlgoExpirationDate constraint if present,
	 * the global {@code getLevel} otherwise.
	 *
	 * @return {@link Level}
	 */
	public Level getAlgoExpirationDateAfterUpdateLevel() {
		AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
		if (algoExpirationDate != null && algoExpirationDate.getLevelAfterUpdate() != null) {
			return algoExpirationDate.getLevelAfterUpdate();
		}
		LevelConstraint levelConstraint = getCryptographicLevelConstraint(algoExpirationDate);
		return levelConstraint != null ? levelConstraint.getLevel() : null;
	}

	/**
	 * Gets the constraint
	 *
	 * @return {@link CryptographicConstraint}
	 */
	public CryptographicConstraint getConstraint() {
		return constraint;
	}

}
