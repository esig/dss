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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.utils.Utils;

public class CryptographicConstraintWrapper {

	private static final Logger LOG = LoggerFactory.getLogger(CryptographicConstraintWrapper.class);

	private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	private final CryptographicConstraint constraint;

	public CryptographicConstraintWrapper(CryptographicConstraint constraint) {
		this.constraint = constraint;
	}

	public List<String> getSupportedEncryptionAlgorithms() {
		return extract(constraint.getAcceptableEncryptionAlgo());
	}

	public List<String> getSupportedDigestAlgorithms() {
		return extract(constraint.getAcceptableDigestAlgo());
	}

	public Map<String, Integer> getMinimumKeySizes() {
		Map<String, Integer> result = new HashMap<String, Integer>();
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
		return result;
	}
	
	public Date getExpirationDate(String algoToSearch, Integer keyLength) {
		TreeMap<Integer, Date> dates = new TreeMap<Integer, Date>();
		AlgoExpirationDate expirations = constraint.getAlgoExpirationDate();
		if(expirations == null) 
			return null;
		SimpleDateFormat dateFormat = new SimpleDateFormat(Utils.isStringEmpty(expirations.getFormat()) ? DEFAULT_DATE_FORMAT : expirations.getFormat());
		
		for (Algo algo : expirations.getAlgo()) {
			if(algo.getValue().equals(algoToSearch)) {
				String expirationDate = algo.getDate();
				try {
					dates.put(algo.getSize(), dateFormat.parse(expirationDate));
				} catch (ParseException e) {
					LOG.warn("Unable to parse '{}' with format '{}'", expirationDate, dateFormat);
				}
			}
		}
		if(dates == null || dates.isEmpty()) {
			return null;
		}
		
		Entry<Integer, Date> floorEntry = dates.floorEntry(keyLength);
		
		if(floorEntry == null)
			return null;
		
		return floorEntry.getValue();
	}

	public Date getDigestAlgorithmExpirationDate(String digestAlgoToSearch) {
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
		
		return null;
	}
	
	public Map<String, Date> getExpirationTimes() {
		Map<String, Date> result = new HashMap<String, Date>();
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
		return result;
	}	

	private List<String> extract(ListAlgo listAlgo) {
		List<String> result = new ArrayList<String>();
		if (listAlgo != null && Utils.isCollectionNotEmpty(listAlgo.getAlgo())) {
			for (Algo algo : listAlgo.getAlgo()) {
				result.add(algo.getValue());
			}
		}
		return result;
	}

}
