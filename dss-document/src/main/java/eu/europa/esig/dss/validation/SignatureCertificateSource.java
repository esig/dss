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
package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * The advanced signature contains a list of certificate that was needed to validate the signature. This class is a
 * basic skeleton that is able to retrieve the needed certificate from a list. The child need to retrieve the list of
 * wrapped certificates.
 *
 */
@SuppressWarnings("serial")
public abstract class SignatureCertificateSource extends CommonCertificateSource {
	
	private static final Logger LOG = LoggerFactory.getLogger(SignatureCertificateSource.class);
	
	/**
	 * Contains a list of all found {@link CertificateRef}s
	 */
	private List<CertificateRef> certificateRefs;
	
	/**
	 * Contains a list of found {@link CertificateRef}s for each {@link CertificateToken}
	 */
	private transient Map<CertificateToken, List<CertificateRef>> certificateRefsMap;
	
	/**
	 * List of orphan {@link CertificateRef}s
	 */
	private List<CertificateRef> orphanCertificateRefs;

	/**
	 * The default constructor with mandatory certificates pool.
	 *
	 * @param certPool
	 *            the certificate pool
	 */
	protected SignatureCertificateSource(final CertificatePool certPool) {
		super(certPool);
	}

	/**
	 * Retrieves the list of all certificates present in the KeyInfos
	 *
	 * @return list of all certificates present in B level
	 */
	public abstract List<CertificateToken> getKeyInfoCertificates();

	/**
	 * Retrieves the list of all certificates from CertificateValues (XAdES/CAdES)
	 * 
	 * @return the list of all certificates present in the CertificateValues
	 */
	public abstract List<CertificateToken> getCertificateValues();

	/**
	 * Retrieves the list of all certificates from the AttrAuthoritiesCertValues
	 * (XAdES)
	 * 
	 * @return the list of all certificates present in the AttrAuthoritiesCertValues
	 */
	public abstract List<CertificateToken> getAttrAuthoritiesCertValues();

	/**
	 * Retrieves the list of all certificates from the TimeStampValidationData
	 * (XAdES)
	 * 
	 * @return the list of all certificates present in the TimeStampValidationData
	 */
	public abstract List<CertificateToken> getTimeStampValidationDataCertValues();

	/**
	 * Retrieves the list of all certificates from the DSS dictionary (PAdES)
	 * 
	 * @return the list of all certificates present in the DSS dictionary
	 */
	public List<CertificateToken> getDSSDictionaryCertValues() {
		return Collections.emptyList();
	}

	/**
	 * Retrieves the list of all certificates from the VRI dictionary (PAdES)
	 * 
	 * @return the list of all certificates present in the VRI dictionary
	 */
	public List<CertificateToken> getVRIDictionaryCertValues() {
		return Collections.emptyList();
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s for the signing certificate
	 * (V1/V2)
	 * 
	 * @return the list of references to the signing certificate
	 */
	public abstract List<CertificateRef> getSigningCertificateValues();
	
	/**
	 * Retrieves the list of {@link CertificateToken}s for the signing certificate (V1/V2)
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getSigningCertificates() {
		return findTokensFromRefs(getSigningCertificateValues());
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s included in the attribute
	 * complete-certificate-references (CAdES) or the
	 * CompleteCertificateRefs/CompleteCertificateRefsV2 (XAdES)
	 * 
	 * @return the list of certificate references
	 */
	public abstract List<CertificateRef> getCompleteCertificateRefs();
	
	/**
	 * Retrieves the list of {@link CertificateToken}s according references to included in the attribute
	 * complete-certificate-references (CAdES) or the
	 * CompleteCertificateRefs/CompleteCertificateRefsV2 (XAdES)
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getCompleteCertificates() {
		return findTokensFromRefs(getCompleteCertificateRefs());
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s included in the attribute
	 * attribute-certificate-references (CAdES) or the
	 * AttributeCertificateRefs/AttributeCertificateRefsV2 (XAdES)
	 * 
	 * @return the list of certificate references
	 */
	public abstract List<CertificateRef> getAttributeCertificateRefs();
	
	/**
	 * Retrieves the list of {@link CertificateToken}s according to references included in the attribute
	 * attribute-certificate-references (CAdES) or the
	 * AttributeCertificateRefs/AttributeCertificateRefsV2 (XAdES)
	 * 
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getAttributeCertificates() {
		return findTokensFromRefs(getAttributeCertificateRefs());
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.SIGNATURE;
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
		List<CertificateToken> tokensFromRefs = new ArrayList<CertificateToken>();
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
	
	public List<CertificateRef> getAllCertificateRefs() {
		if (certificateRefs == null) {
			certificateRefs = new ArrayList<CertificateRef>();
			certificateRefs.addAll(getCompleteCertificateRefs());
			certificateRefs.addAll(getAttributeCertificateRefs());
			certificateRefs.addAll(getSigningCertificateValues());
		}
		return certificateRefs;
	}
	
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
		certificateRefsMap = new HashMap<CertificateToken, List<CertificateRef>>();
		for (CertificateToken certificateToken : getCertificates()) {
			for (CertificateRef certificateRef : getAllCertificateRefs()) {
				Digest certDigest = certificateRef.getCertDigest();
				IssuerSerialInfo issuerInfo = certificateRef.getIssuerInfo();
				if (certDigest != null) {
					byte[] currentDigest = certificateToken.getDigest(certDigest.getAlgorithm());
					if (Arrays.equals(currentDigest, certDigest.getValue())) {
						addCertificateRefToMap(certificateToken, certificateRef);
					}
					
				} else if (issuerInfo != null && 
						certificateToken.getSerialNumber().equals(issuerInfo.getSerialNumber()) && 
						DSSUtils.x500PrincipalAreEquals(certificateToken.getIssuerX500Principal(), issuerInfo.getIssuerName())) {
					addCertificateRefToMap(certificateToken, certificateRef);
					
				}
			}
		}
	}
	
	private void addCertificateRefToMap(CertificateToken certificateToken, CertificateRef certificateRef) {
		List<CertificateRef> certificateRefs = certificateRefsMap.get(certificateToken);
		if (certificateRefs == null) {
			certificateRefs = new ArrayList<CertificateRef>();
			certificateRefsMap.put(certificateToken, certificateRefs);
		}
		certificateRefs.add(certificateRef);
	}
	
	/**
	 * Returns a list of orphan certificate refs
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getOrphanCertificateRefs() {
		if (orphanCertificateRefs == null) {
			orphanCertificateRefs = new ArrayList<CertificateRef>();
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

	protected IssuerSerialInfo getIssuerInfo(IssuerSerial issuerAndSerial) {
		try {
			IssuerSerialInfo issuerInfo = new IssuerSerialInfo();
			GeneralNames gnames = issuerAndSerial.getIssuer();
			if (gnames != null) {
				GeneralName[] names = gnames.getNames();
				if (names.length == 1) {
					issuerInfo.setIssuerName(new X500Principal(names[0].getName().toASN1Primitive().getEncoded(ASN1Encoding.DER)));
				} else {
					LOG.warn("More than one GeneralName");
				}
			}

			ASN1Integer serialNumber = issuerAndSerial.getSerial();
			if (serialNumber != null) {
				issuerInfo.setSerialNumber(serialNumber.getValue());
			}

			return issuerInfo;
		} catch (Exception e) {
			LOG.error("Unable to read the IssuerSerial object", e);
			return null;
		}
	}

}
