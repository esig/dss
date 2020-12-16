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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
	 * Returns a list of supported Encryption algorithm names
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getSupportedEncryptionAlgorithms() {
		if (constraint != null) {
			return extract(constraint.getAcceptableEncryptionAlgo());
		}
		return Collections.emptyList();
	}

	/**
	 * Returns a list of supported Digest algorithm names
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getSupportedDigestAlgorithms() {
		if (constraint != null) {
			return extract(constraint.getAcceptableDigestAlgo());
		}
		return Collections.emptyList();
	}

	/**
	 * Returns a map of minimum accepted key sizes for different Encryption algorithms
	 *
	 * @return a map of minimum accepted key sizes
	 */
	public Map<String, Integer> getMinimumKeySizes() {
		Map<String, Integer> result = new HashMap<>();
		if (constraint != null) {
			ListAlgo miniPublicKeySize = constraint.getMiniPublicKeySize();
			if (miniPublicKeySize != null && Utils.isCollectionNotEmpty(miniPublicKeySize.getAlgo())) {
				for (Algo algo : miniPublicKeySize.getAlgo()) {
					Integer size = algo.getSize();
					if (size != null) {
						result.put(algo.getValue(), size);
					} else {
						result.put(algo.getValue(), 0);
					}
				}
			}
		}
		return result;
	}

	/**
	 * Gets an expiration date for the encryption algorithm with name {@code algoToSearch} and {@code keyLength}
	 *
	 * @param algoToSearch {@link String} name of the encryption algorithm
	 * @param keyLength {@link Integer} key length used to sign the token
	 * @return {@link Date}
	 */
	public Date getExpirationDate(String algoToSearch, Integer keyLength) {
		TreeMap<Integer, Date> dates = new TreeMap<>();
		if (constraint != null) {
			AlgoExpirationDate expirations = constraint.getAlgoExpirationDate();
			if (expirations == null) {
				return null;
			}
			SimpleDateFormat dateFormat = new SimpleDateFormat(Utils.isStringEmpty(expirations.getFormat()) ? DEFAULT_DATE_FORMAT : expirations.getFormat());
	
			for (Algo algo : expirations.getAlgo()) {
				if (algo.getValue().equals(algoToSearch)) {
					String expirationDate = algo.getDate();
					try {
						dates.put(algo.getSize(), dateFormat.parse(expirationDate));
					} catch (ParseException e) {
						LOG.warn("Unable to parse '{}' with format '{}'", expirationDate, dateFormat);
					}
				}
			}
		}

		Entry<Integer, Date> floorEntry = dates.floorEntry(keyLength);
		if (floorEntry == null) {
			return null;
		} else {
			return floorEntry.getValue();
		}
	}

	/**
	 * Gets an expiration date for the digest algorithm with name {@code digestAlgoToSearch}
	 *
	 * @param digestAlgoToSearch {@link String} name of the digest algorithm
	 * @return {@link Date}
	 */
	public Date getDigestAlgorithmExpirationDate(String digestAlgoToSearch) {
		if (constraint != null) {
			AlgoExpirationDate expirations = constraint.getAlgoExpirationDate();
			if(expirations == null)
				return null;
			SimpleDateFormat dateFormat = new SimpleDateFormat(Utils.isStringEmpty(expirations.getFormat()) ? DEFAULT_DATE_FORMAT : expirations.getFormat());
	
			for (Algo algo : expirations.getAlgo()) {
				if(algo.getValue().equals(digestAlgoToSearch)) {
					String expirationDate = algo.getDate();
					try {
						return dateFormat.parse(expirationDate);
					} catch (ParseException e) {
						LOG.warn("Unable to parse '{}' with format '{}'", expirationDate, dateFormat);
					}
				}
			}
		}
		
		return null;
	}

	/**
	 * Returns a map of all defined algorithm expiration times
	 *
	 * @return a map of algorithm names and the corresponding expiration times
	 */
	public Map<String, Date> getExpirationTimes() {
		Map<String, Date> result = new HashMap<>();
		if (constraint != null) {
			AlgoExpirationDate expirations = constraint.getAlgoExpirationDate();
			if (expirations != null && Utils.isCollectionNotEmpty(expirations.getAlgo())) {
				SimpleDateFormat dateFormat = new SimpleDateFormat(Utils.isStringEmpty(expirations.getFormat()) ? DEFAULT_DATE_FORMAT : expirations.getFormat());
				for (Algo algo : expirations.getAlgo()) {
					String currentAlgo = algo.getValue();
					String expirationDate = algo.getDate();
					try {
						result.put(currentAlgo, dateFormat.parse(expirationDate));
					} catch (ParseException e) {
						LOG.warn("Unable to parse '{}' with format '{}'", expirationDate, dateFormat);
					}
				}
			}
		}
		return result;
	}

	/**
	 * Extracts a list of algorithm names from {@code ListAlgo}
	 *
	 * @param listAlgo {@link ListAlgo}
	 * @return a list of {@link String}
	 */
	private List<String> extract(ListAlgo listAlgo) {
		List<String> result = new ArrayList<>();
		if (listAlgo != null && Utils.isCollectionNotEmpty(listAlgo.getAlgo())) {
			for (Algo algo : listAlgo.getAlgo()) {
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
