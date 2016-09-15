package eu.europa.esig.dss.validation.process.vpfswatsp;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjects;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampReferenceCategory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.RevocationOrigin;

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

	private Map<String, List<Date>> poe = new HashMap<String, List<Date>>();

	public void init(DiagnosticData diagnosticData, Date currentTime) {
		Set<SignatureWrapper> signatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signature : signatures) {
			addPOE(signature.getId(), currentTime);
		}
		Set<TimestampWrapper> timestamps = diagnosticData.getAllTimestamps();
		for (TimestampWrapper timestamp : timestamps) {
			addPOE(timestamp.getId(), currentTime);
		}
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificate : usedCertificates) {
			addPOE(certificate.getId(), currentTime);
			Set<RevocationWrapper> revocations = certificate.getRevocationData();
			if (Utils.isCollectionNotEmpty(revocations)) {
				for (RevocationWrapper revocation : revocations) {
					if (RevocationOrigin.SIGNATURE.name().equals(revocation.getOrigin())) {
						addPOE(revocation.getId(), currentTime);
					}
				}
			}
		}
	}

	public void extractPOE(TimestampWrapper timestamp, DiagnosticData diagnosticData) {

		Date productionTime = timestamp.getProductionTime();

		XmlSignedObjects signedObjects = timestamp.getSignedObjects();
		if (signedObjects != null) {
			if (Utils.isCollectionNotEmpty(signedObjects.getSignedSignature())) {
				// SIGNATURES and TIMESTAMPS
				for (XmlSignedSignature signedSignature : signedObjects.getSignedSignature()) {
					addPOE(signedSignature.getId(), productionTime);
				}
				for (XmlTimestampedTimestamp timstampedTimastamp : signedObjects.getTimestampedTimestamp()) {
					addPOE(timstampedTimastamp.getId(), productionTime);
				}
			}

			List<XmlDigestAlgoAndValue> digestAlgoAndValues = signedObjects.getDigestAlgoAndValues();
			if (Utils.isCollectionNotEmpty(digestAlgoAndValues)) {
				for (XmlDigestAlgoAndValue digestAlgoAndValue : digestAlgoAndValues) {
					if (Utils.areStringsEqual(TimestampReferenceCategory.CERTIFICATE.name(), digestAlgoAndValue.getCategory())) {
						String certificateId = getCertificateIdByDigest(digestAlgoAndValue, diagnosticData);
						if (certificateId != null) {
							addPOE(certificateId, productionTime);
						}
					} else if (Utils.areStringsEqual(TimestampReferenceCategory.REVOCATION.name(), digestAlgoAndValue.getCategory())) {
						String revocationId = getRevocationIdByDigest(digestAlgoAndValue, diagnosticData);
						if (revocationId != null) {
							addPOE(revocationId, productionTime);
						}
					}
				}
			}
		}
	}

	private String getCertificateIdByDigest(XmlDigestAlgoAndValue digestAlgoValue, DiagnosticData diagnosticData) {
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		if (Utils.isCollectionNotEmpty(certificates)) {
			for (CertificateWrapper certificate : certificates) {
				List<XmlDigestAlgoAndValue> digestAlgAndValues = certificate.getDigestAlgoAndValues();
				if (Utils.isCollectionNotEmpty(digestAlgAndValues)) {
					for (XmlDigestAlgoAndValue certificateDigestAndValue : digestAlgAndValues) {
						if (Utils.areStringsEqual(certificateDigestAndValue.getDigestMethod(), digestAlgoValue.getDigestMethod())
								&& Utils.areStringsEqual(certificateDigestAndValue.getDigestValue(), digestAlgoValue.getDigestValue())) {
							return certificate.getId();
						}
					}
				}
			}
		}
		return null;
	}

	private String getRevocationIdByDigest(XmlDigestAlgoAndValue digestAlgoValue, DiagnosticData diagnosticData) {
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		if (Utils.isCollectionNotEmpty(certificates)) {
			for (CertificateWrapper certificate : certificates) {
				Set<RevocationWrapper> revocations = certificate.getRevocationData();
				if (Utils.isCollectionNotEmpty(revocations)) {
					for (RevocationWrapper revocationData : revocations) {
						List<XmlDigestAlgoAndValue> digestAlgAndValues = revocationData.getDigestAlgoAndValues();
						for (XmlDigestAlgoAndValue revocDigestAndValue : digestAlgAndValues) {
							if (Utils.areStringsEqual(revocDigestAndValue.getDigestMethod(), digestAlgoValue.getDigestMethod())
									&& Utils.areStringsEqual(revocDigestAndValue.getDigestValue(), digestAlgoValue.getDigestValue())) {
								return revocationData.getId();
							}
						}
					}
				}
			}
		}
		return null;
	}

	private void addPOE(String poeId, Date productionTime) {
		if (productionTime != null) {
			List<Date> datesById = poe.get(poeId);
			if (datesById == null) {
				datesById = new ArrayList<Date>();
				poe.put(poeId, datesById);
			}
			datesById.add(productionTime);
		}
	}

	/**
	 * Returns true if there is a POE exists for a given id at (or before) the control time.
	 * 
	 */
	public boolean isPOEExists(final String id, final Date controlTime) {
		List<Date> dates = poe.get(id);
		if (dates != null) {
			for (Date date : dates) {
				if (date.compareTo(controlTime) < 0) {
					return true;
				}
			}
		}
		return false;
	}

	public Date getLowestPOE(final String id, final Date controlTime) {
		Date lowestDate = null;
		List<Date> dates = poe.get(id);
		if (dates != null) {
			for (Date date : dates) {
				if (date.compareTo(controlTime) <= 0) {
					if (lowestDate == null) {
						lowestDate = date;
					} else if (lowestDate.after(date)) {
						lowestDate = date;
					}
				}
			}
		}
		return lowestDate;
	}

}
