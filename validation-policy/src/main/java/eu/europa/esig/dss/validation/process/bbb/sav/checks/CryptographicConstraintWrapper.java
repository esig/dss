/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
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
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;

/**
 * The wrapper for a cryptographic information retrieved from a validation policy
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
			if (acceptableEncryptionAlgos != null) {
				for (Algo algo : acceptableEncryptionAlgos.getAlgos()) {
					if (algo.getValue().equals(encryptionAlgorithm.getName())) {
						return true;
					}
				}
			}
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
			ListAlgo acceptableEncryptionAlgos = constraint.getAcceptableDigestAlgo();
			if (acceptableEncryptionAlgos != null) {
				for (Algo algo : acceptableEncryptionAlgos.getAlgos()) {
					if (algo.getValue().equals(digestAlgorithm.getName())) {
						return true;
					}
				}
			}
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
		if (encryptionAlgorithm != null && keySize != 0 && constraint != null) {
			ListAlgo miniPublicKeySize = constraint.getMiniPublicKeySize();
			if (miniPublicKeySize != null) {
				for (Algo algo : miniPublicKeySize.getAlgos()) {
					if (algo.getValue().equals(encryptionAlgorithm.getName())) {
						Integer size = algo.getSize();
						if (size != null && size <= keySize) {
							return true;
						}
					}
				}
			}
		}
		return false;
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
		TreeMap<Integer, Date> dates = new TreeMap<>();
		AlgoExpirationDate algoExpirationDates = getAlgoExpirationDates();
		if (algoExpirationDates != null && encryptionAlgorithm != null) {
			SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
			String algoToSearch = encryptionAlgorithm.getName();
			for (Algo algo : algoExpirationDates.getAlgos()) {
				if (algo.getValue().equals(algoToSearch)) {
					dates.put(algo.getSize(), getDate(algo, dateFormat));
				}
			}
		}

		int keySize = parseKeySize(keyLength);
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
			SimpleDateFormat dateFormat = getUsedDateFormat(algoExpirationDates);
			String algoToFind = digestAlgorithm.getName();
			for (Algo algo : algoExpirationDates.getAlgos()) {
				if (algo.getValue().equals(algoToFind)) {
					return getDate(algo, dateFormat);
				}
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
		String date = algo.getDate();
		if (date != null) {
			try {
				return format.parse(date);
			} catch (ParseException e) {
				LOG.warn("Unable to parse '{}' with format '{}'", date, format);
			}
		}
		return null;
	}

	/**
	 * Extracts a list of algorithm names from {@code ListAlgo}
	 *
	 * @param listAlgo {@link ListAlgo}
	 * @return a list of {@link String}
	 */
	private List<String> extract(ListAlgo listAlgo) {
		List<String> result = new ArrayList<>();
		if (listAlgo != null && Utils.isCollectionNotEmpty(listAlgo.getAlgos())) {
			for (Algo algo : listAlgo.getAlgos()) {
				result.add(algo.getValue());
			}
		}
		return result;
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
