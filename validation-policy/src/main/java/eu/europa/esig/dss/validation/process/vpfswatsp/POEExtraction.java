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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
	private final Map<String, List<POE>> poeMap = new HashMap<>();

	/**
	 * Default constructor initializing an empty map
	 */
	public POEExtraction() {
		// empty
	}

	/**
	 * Instantiates a controlTime POE for all used tokens
	 * 
	 * @param diagnosticData {@link DiagnosticData} containing all tokens to initialize the POE for
	 * @param controlTime {@link Date} defining the time of POE
	 */
	public void init(DiagnosticData diagnosticData, Date controlTime) {
		
		POE controlTimePoe = new POE(controlTime);

		for (SignatureWrapper signature : diagnosticData.getAllSignatures()) {
			addPOE(signature.getId(), controlTimePoe);
		}
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			addPOE(timestamp.getId(), controlTimePoe);
		}
		for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {
			addPOE(evidenceRecord.getId(), controlTimePoe);
		}
		for (CertificateWrapper certificate : diagnosticData.getUsedCertificates()) {
			addPOE(certificate.getId(), controlTimePoe);
		}
		for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
			addPOE(revocation.getId(), controlTimePoe);
		}
		for (SignerDataWrapper signerData : diagnosticData.getAllSignerDocuments()) {
			addPOE(signerData.getId(), controlTimePoe);
		}
		for (OrphanTokenWrapper<?> orphanCertificate : diagnosticData.getAllOrphanCertificateObjects()) {
			addPOE(orphanCertificate.getId(), controlTimePoe);
		}
		for (OrphanTokenWrapper<?> orphanCertificateRef : diagnosticData.getAllOrphanCertificateReferences()) {
			addPOE(orphanCertificateRef.getId(), controlTimePoe);
		}
		for (OrphanTokenWrapper<?> orphanRevocation : diagnosticData.getAllOrphanRevocationObjects()) {
			addPOE(orphanRevocation.getId(), controlTimePoe);
		}
		for (OrphanTokenWrapper<?> orphanRevocationRef : diagnosticData.getAllOrphanRevocationReferences()) {
			addPOE(orphanRevocationRef.getId(), controlTimePoe);
		}
		
	}
	
	/**
	 * Extracts all POEs from the provided collection of timestamps
	 * 
	 * @param timestamps a collection of {@link TimestampWrapper}s
	 */
	public void collectAllPOE(Collection<TimestampWrapper> timestamps) {
		for (TimestampWrapper timestamp : timestamps) {
			extractPOE(timestamp);
		}
	}

	/**
	 * Extracts POE for all covered objects from a single timestamp wrapper
	 * 
	 * @param timestamp {@link TimestampWrapper} to extract POE from
	 */
	public void extractPOE(TimestampWrapper timestamp) {
		/*
		 * 5.6.2.3.4 Processing (5.6.2.3 POE extraction)
		 *
		 * 1) The building block shall determine the set S of references to objects and
		 * objects that are part of the signature and are protected by the time-stamp.
		 */
		if (timestamp.isMessageImprintDataFound() && timestamp.isMessageImprintDataIntact()) {
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			if (Utils.isCollectionNotEmpty(timestampedObjects)) {
				POE poe = new TimestampPOE(timestamp);
				for (XmlTimestampedObject xmlTimestampedObject : timestampedObjects) {
					addPOE(xmlTimestampedObject.getToken().getId(), poe);
				}
			}
		}
	}

	/**
	 * Extracts POE for all objects covered by an evidence record
	 *
	 * @param evidenceRecord {@link EvidenceRecordWrapper}
	 */
	public void extractPOE(EvidenceRecordWrapper evidenceRecord) {
		List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
		if (Utils.isCollectionNotEmpty(coveredObjects)) {
			POE poe = new EvidenceRecordPOE(evidenceRecord);
			for (XmlTimestampedObject xmlTimestampedObject : coveredObjects) {
				addPOE(xmlTimestampedObject.getToken().getId(), poe);
			}
		}
	}

	/**
	 * Extracts POE for given timestamped objects
	 *
	 * @param timestampedObjects a list of {@link XmlTimestampedObject} to get POE for
	 * @param poeTime to be provided for timestamped objects
	 */
	public void extractPOE(List<XmlTimestampedObject> timestampedObjects, Date poeTime) {
		if (Utils.isCollectionNotEmpty(timestampedObjects) && poeTime != null) {
			POE poe = new POE(poeTime);
			for (XmlTimestampedObject xmlTimestampedObject : timestampedObjects) {
				addPOE(xmlTimestampedObject.getToken().getId(), poe);
			}
		}
	}

	private void addPOE(String tokenId, POE proofOfExistence) {
		if (proofOfExistence != null) {
			List<POE> poesById = poeMap.computeIfAbsent(tokenId, k -> new ArrayList<>());
			poesById.add(proofOfExistence);
		}
	}
	
	/**
	 * Adds a specific POE for a signature wrapper
	 * 
	 * @param signature {@link SignatureWrapper}
	 * @param proofOfExistence {@link POE}
	 */
	public void addSignaturePOE(SignatureWrapper signature, POE proofOfExistence) {
		if (signature != null) {
			addPOE(signature.getId(), proofOfExistence);
		}
	}

	/**
	 * Returns true if there is a POE exists for a given id at (or before) the
	 * control time.
	 * 
	 * @param tokenId     the token id to be find
	 * @param controlTime the control time
	 * @return TRUE if the POE exists, FALSE otherwise
	 */
	public boolean isPOEExists(final String tokenId, final Date controlTime) {
		List<POE> poes = poeMap.get(tokenId);
		if (poes != null) {
			for (POE poe : poes) {
				if (poe.getTime().compareTo(controlTime) <= 0) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Checks if a POE exists for the token with the given Id within the validity range
	 * between {@code notBefore} and {@code notAfter} inclusively
	 *
	 * @param tokenId {@link String} the Id of a token to check POE for
	 * @param notBefore {@link Date} the start of the validity range
	 * @param notAfter {@link Date} the end of the validity range
	 * @return TRUE if a POE exists in the range, FALSE otherwise
	 */
	public boolean isPOEExistInRange(final String tokenId, final Date notBefore, final Date notAfter) {
		List<POE> poes = poeMap.get(tokenId);
		if (poes != null) {
			for (POE poe : poes) {
				if (poe.getTime().compareTo(notBefore) >= 0 && poe.getTime().compareTo(notAfter) <= 0) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns the lowest POE time for the requested token
	 * 
	 * @param tokenId {@link String} is of the token to get the lowest POE time for
	 * @return {@link Date} representing the lowest POE time for the token
	 */
	public Date getLowestPOETime(final String tokenId) {
		return getLowestPOE(tokenId).getTime();
	}

	/**
	 * Returns the lowest POE for the requested token
	 * NOTE: can return NULL if POE is not found (init(controlTime) method must be executed before)
	 * 
	 * @param tokenId {@link String} id of token to get the lowest POE for
	 * @return the lowest {@link POE} for the token
	 */
	public POE getLowestPOE(final String tokenId) {
		POE lowestPOE = null;
		List<POE> poes = poeMap.get(tokenId);
		if (poes != null) {
			POEComparator comparator = new POEComparator();
			for (POE poe : poes) {
				if (lowestPOE == null || comparator.before(poe, lowestPOE)) {
					lowestPOE = poe;
				}
			}
		}
		return lowestPOE;
	}

}
