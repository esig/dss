package eu.europa.esig.dss.spi.x509;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;

/**
 * Represents a source of certificates embedded in a token (signature, timestamp, ocsp response)
 *
 */
@SuppressWarnings("serial")
public abstract class TokenCertificateSource extends CommonCertificateSource {
	
	/**
	 * Contains a list of found {@link CertificateRef}s for each {@link CertificateToken}
	 */
	private transient Map<CertificateToken, List<CertificateRef>> certificateRefsMap;
	
	/**
	 * List of orphan {@link CertificateRef}s
	 */
	private List<CertificateRef> orphanCertificateRefs;
	
	protected TokenCertificateSource() {
		super();
	}

	protected TokenCertificateSource(final CertificatePool certPool) {
		super(certPool);
	}
	
	/**
	 * Returns list of {@link CertificateRef}s found for the given {@code certificateToken}
	 * @param certificateToken {@link CertificateToken} to find references for
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getReferencesForCertificateToken(CertificateToken certificateToken) {
		if (Utils.isMapEmpty(certificateRefsMap)) {
			collectCertificateRefsMap();
		}
		List<CertificateRef> references = certificateRefsMap.get(certificateToken);
		if (references != null) {
			return references;
		} else {
			return Collections.emptyList();
		}
	}

	/**
	 * Returns list of {@link CertificateToken}s for the provided {@link CertificateRef}s
	 * @param certificateRefs list of {@link CertificateRef}s
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> findTokensFromRefs(List<CertificateRef> certificateRefs) {
		if (Utils.isMapEmpty(certificateRefsMap)) {
			collectCertificateRefsMap();
		}
		List<CertificateToken> tokensFromRefs = new ArrayList<>();
		for (Entry<CertificateToken, List<CertificateRef>> certMapEntry : certificateRefsMap.entrySet()) {
			for (CertificateRef reference : certMapEntry.getValue()) {
				if (certificateRefs.contains(reference)) {
					tokensFromRefs.add(certMapEntry.getKey());
					break;
				}
			}
		}
		return tokensFromRefs;
	}
	
	/**
	 * Returns a list of all certificate references
	 * 
	 * @return a list of {@link CertificateRef}s
	 */
	public abstract List<CertificateRef> getAllCertificateRefs();
	
	/**
	 * Returns a contained {@link CertificateRef} with the given {@code digest}
	 * @param digest {@link Digest} to find a {@link CertificateRef} with
	 * @return {@link CertificateRef}
	 */
	public CertificateRef getCertificateRefByDigest(Digest digest) {
		for (CertificateRef certificateRef : getAllCertificateRefs()) {
			if (digest.equals(certificateRef.getCertDigest())) {
				return certificateRef;
			}
		}
		return null;
	}
	
	private void collectCertificateRefsMap() {
		certificateRefsMap = new HashMap<>();
		for (CertificateToken certificateToken : getCertificates()) {
			for (CertificateRef certificateRef : getAllCertificateRefs()) {
				Digest certDigest = certificateRef.getCertDigest();
				IssuerSerialInfo issuerInfo = certificateRef.getIssuerInfo();
				byte[] ski = certificateRef.getSki();
				if (certDigest != null) {
					byte[] currentDigest = certificateToken.getDigest(certDigest.getAlgorithm());
					if (Arrays.equals(currentDigest, certDigest.getValue())) {
						addCertificateRefToMap(certificateToken, certificateRef);
					}
					
				} else if (issuerInfo != null && issuerInfo.isRelatedTo(certificateToken)) {
					addCertificateRefToMap(certificateToken, certificateRef);
				} else if (ski != null) {
					byte[] certSki = DSSASN1Utils.computeSkiFromCert(certificateToken);
					if (Arrays.equals(certSki, ski)) {
						addCertificateRefToMap(certificateToken, certificateRef);
					}
				}
			}
		}
	}
	
	private void addCertificateRefToMap(CertificateToken certificateToken, CertificateRef certificateRef) {
		List<CertificateRef> currentCertificateRefs = certificateRefsMap.get(certificateToken);
		if (currentCertificateRefs == null) {
			currentCertificateRefs = new ArrayList<>();
			certificateRefsMap.put(certificateToken, currentCertificateRefs);
		}
		currentCertificateRefs.add(certificateRef);
	}
	
	/**
	 * Returns a list of orphan certificate refs
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getOrphanCertificateRefs() {
		if (orphanCertificateRefs == null) {
			orphanCertificateRefs = new ArrayList<>();
			if (Utils.isMapEmpty(certificateRefsMap)) {
				collectCertificateRefsMap();
			}
			for (CertificateRef certificateRef : getAllCertificateRefs()) {
				boolean found = false;
				for (List<CertificateRef> assignedCertificateRefs : certificateRefsMap.values()) {
					if (assignedCertificateRefs.contains(certificateRef)) {
						found = true;
						break;
					}
				}
				if (!found) {
					orphanCertificateRefs.add(certificateRef);
				}
			}
		}
		return orphanCertificateRefs;
	}

}
