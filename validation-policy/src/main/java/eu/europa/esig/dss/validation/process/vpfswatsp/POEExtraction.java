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
package eu.europa.esig.dss.validation.process.vpfswatsp;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.utils.Utils;

/**
 * 5.6.2.3 POE extraction
 * 5.6.2.3.1 Description
 * This building block derives POEs from a given time-stamp. Assumptions:
 * - The time-stamp validation has returned PASSED.
 * - The cryptographic hash function used in the time-stamp (messageImprint.hashAlgorithm) is considered
 * reliable at current time or, if this is not the case, a PoE for that time-stamp exists for a time when the hash
 * function has still been considered reliable.
 * In the simple case, a time-stamp gives a POE for each data item protected by the time-stamp at the generation
 * date/time of the token.
 * EXAMPLE: A time-stamp on the signature value gives a POE of the signature value at the generation date/time
 * of the time-stamp.
 * A time-stamp can also give an indirect POE when it is computed on the hash value of some data instead of the data
 * itself. A POE for DATA at T1 can be derived from the time-stamp:
 * - If there is a POE for h(DATA) at a date T1,where h is a cryptographic hash function and DATA is some data
 * (e.g. a certificate),
 * - if h is asserted in the cryptographic constraints to be trusted until at least a date T after T1; and
 * - if there is a POE for DATA at a date T after T1.
 */
public class POEExtraction {

	/**
	 * Map of proofs of existence by token ids
	 */
	private Map<String, List<XmlProofOfExistence>> poe = new HashMap<String, List<XmlProofOfExistence>>();

	public void init(DiagnosticData diagnosticData, XmlProofOfExistence proofOfExistence) {

		Set<SignatureWrapper> signatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signature : signatures) {
			addPOE(signature.getId(), proofOfExistence);
		}
		Set<TimestampWrapper> timestamps = diagnosticData.getTimestampSet();
		for (TimestampWrapper timestamp : timestamps) {
			addPOE(timestamp.getId(), proofOfExistence);
		}
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificate : usedCertificates) {
			addPOE(certificate.getId(), proofOfExistence);
			List<CertificateRevocationWrapper> revocations = certificate.getCertificateRevocationData();
			if (Utils.isCollectionNotEmpty(revocations)) {
				for (CertificateRevocationWrapper revocation : revocations) {
					addPOE(revocation.getId(), proofOfExistence);
				}
			}
		}
	}
	
	public void collectAllPOE(DiagnosticData diagnosticData) {
		for (TimestampWrapper timestamp : diagnosticData.getTimestampSet()) {
			extractPOE(timestamp);
		}
	}

	public void extractPOE(TimestampWrapper timestamp) {
		List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
		if (Utils.isCollectionNotEmpty(timestampedObjects)) {
			XmlProofOfExistence poe = new XmlProofOfExistence();
			poe.setTimestampId(timestamp.getId());
			poe.setTime(timestamp.getProductionTime());

			for (XmlTimestampedObject xmlTimestampedObject : timestampedObjects) {
				addPOE(xmlTimestampedObject.getToken().getId(), poe);
			}
		}
	}

	private void addPOE(String tokenId, XmlProofOfExistence proofOfExistence) {
		if (proofOfExistence != null) {
			List<XmlProofOfExistence> poesById = poe.get(tokenId);
			if (poesById == null) {
				poesById = new ArrayList<XmlProofOfExistence>();
				poe.put(tokenId, poesById);
			}
			poesById.add(proofOfExistence);
		}
	}
	
	public void addSignaturePOE(SignatureWrapper signature, XmlProofOfExistence proofOfExistence) {
		if (signature != null) {
			addPOE(signature.getId(), proofOfExistence);
		}
	}

	/**
	 * Returns true if there is a POE exists for a given id at (or before) the control time.
	 * 
	 */
	public boolean isPOEExists(final String tokenId, final Date controlTime) {
		List<XmlProofOfExistence> poes = poe.get(tokenId);
		if (poes != null) {
			for (XmlProofOfExistence poe : poes) {
				if (poe.getTime().compareTo(controlTime) <= 0) {
					return true;
				}
			}
		}
		return false;
	}

	public Date getLowestPOETime(final String tokenId, final Date controlTime) {
		return getLowestPOE(tokenId, controlTime).getTime();
	}

	public XmlProofOfExistence getLowestPOE(final String tokenId, final Date controlTime) {
		XmlProofOfExistence lowestPOE = new XmlProofOfExistence();
		lowestPOE.setTime(controlTime);
		List<XmlProofOfExistence> poes = poe.get(tokenId);
		if (poes != null) {
			for (XmlProofOfExistence poe : poes) {
				if (poe.getTime().compareTo(lowestPOE.getTime()) <= 0) {
					lowestPOE = poe;
				}
			}
		}
		return lowestPOE;
	}

}
