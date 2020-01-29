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
package eu.europa.esig.dss.pades.validation;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESTimestampSource;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

@SuppressWarnings("serial")
public class PAdESTimestampSource extends CAdESTimestampSource {
	
	private final transient PdfRevision pdfSignatureRevision;
	
	public PAdESTimestampSource(final PAdESSignature signature, final CertificatePool certificatePool) {
		super(signature, certificatePool);
		this.pdfSignatureRevision = signature.getPdfRevision();
	}
	
	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		if (getSignatureTimestamps() == null || getArchiveTimestamps() == null) {
			createAndValidate();
		}
		List<TimestampToken> documentTimestamps = new ArrayList<>();
		documentTimestamps.addAll(getSignatureTimestamps());
		documentTimestamps.addAll(getArchiveTimestamps());
		return documentTimestamps;
	}

	@Override
	protected PAdESTimestampDataBuilder getTimestampDataBuilder() {
		PAdESTimestampDataBuilder padesTimestampDataBuilder = new PAdESTimestampDataBuilder(pdfSignatureRevision, signerInformation, detachedDocuments);
		padesTimestampDataBuilder.setSignatureTimestamps(getSignatureTimestamps());
		return padesTimestampDataBuilder;
	}

	@Override
	protected void makeTimestampTokens() {
		// Creates signature timestamp tokens only (from CAdESTimestampSource)
		super.makeTimestampTokens();
		
		List<TimestampToken> cadesSignatureTimestamps = getSignatureTimestamps();
		final List<TimestampToken> timestampedTimestamps = new ArrayList<>(cadesSignatureTimestamps);
		
		// contains KeyInfo certificates embedded to the timestamp's content
		final List<CertificateToken> cmsContentCertificates = new ArrayList<>();
		
		final List<PdfRevision> outerSignatures = pdfSignatureRevision.getOuterSignatures();
		for (final PdfRevision outerSignature : outerSignatures) {
			
			if (outerSignature.isTimestampRevision() && (outerSignature instanceof PdfDocTimestampRevision)) {
				final PdfDocTimestampRevision timestampInfo = (PdfDocTimestampRevision) outerSignature;
				final TimestampToken timestampToken = timestampInfo.getTimestampToken();
				if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
					timestampToken.getTimestampedReferences().addAll(getSignatureTimestampReferences());
					cadesSignatureTimestamps.add(timestampToken);
					
				} else {
					// Archive TimeStamps
					timestampToken.setArchiveTimestampType(getArchiveTimestampType());
					
					List<TimestampedReference> references = new ArrayList<>();
					if (Utils.isCollectionEmpty(cadesSignatureTimestamps)) {
						references = getSignatureTimestampReferences();
					}
					addReferencesForPreviousTimestamps(references, timestampedTimestamps);
					
					// extract timestamped references from the timestamped DSS Dictionary
					final PdfDssDict coveredDSSDictionary = timestampInfo.getDssDictionary();
					final PAdESCertificateSource padesCertificateSource = new PAdESCertificateSource(
							coveredDSSDictionary, timestampInfo.getCMSSignedData(), certificatePool);

					addReferences(references, createReferencesForCertificates(cmsContentCertificates));
					addReferencesForCertificates(references, padesCertificateSource);
					addReferencesFromRevocationData(references, timestampInfo);
					
					// references embedded to timestamp's content are covered by outer timestamps
					cmsContentCertificates.addAll(getCMSContentReferences(padesCertificateSource));
					addReferences(timestampToken.getTimestampedReferences(), references);
					getArchiveTimestamps().add(timestampToken);
					
				}
				populateTimestampCertificateSource(timestampToken.getCertificates());
				timestampedTimestamps.add(timestampToken);
				
			}
		}
	}
	
	@Override
	protected List<TimestampedReference> getSignatureTimestampReferences() {
		List<TimestampedReference> signatureTimestampReferences = super.getSignatureTimestampReferences();
		// timestamp covers inner signature, therefore it covers certificates included into the signature's KeyInfo
		addReferences(signatureTimestampReferences, createReferencesForCertificates(signatureCertificateSource.getKeyInfoCertificates()));
		return signatureTimestampReferences;
	}
	
	private List<CertificateToken> getCMSContentReferences(final PAdESCertificateSource padesCertificateSource) {
		// timestamp covers its own cms content
		List<CertificateToken> keyInfoCertificates = padesCertificateSource.getKeyInfoCertificates();
		populateTimestampCertificateSource(keyInfoCertificates);
		return keyInfoCertificates;
	}

	private void addReferencesForCertificates(List<TimestampedReference> references, final PAdESCertificateSource padesCertificateSource) {
		
		List<CertificateToken> dssDictionaryCertValues = padesCertificateSource.getDSSDictionaryCertValues();
		addReferences(references, createReferencesForCertificates(dssDictionaryCertValues));
		populateTimestampCertificateSource(dssDictionaryCertValues);
		
		List<CertificateToken> vriDictionaryCertValues = padesCertificateSource.getVRIDictionaryCertValues();
		addReferences(references, createReferencesForCertificates(vriDictionaryCertValues));
		populateTimestampCertificateSource(vriDictionaryCertValues);
	}

	/**
	 * This method adds references to retrieved revocation data.
	 * 
	 * @param references
	 */
	private void addReferencesFromRevocationData(List<TimestampedReference> references, final PdfDocTimestampRevision timestampInfo) {
		SignerInformation signerInformation = timestampInfo.getTimestampToken().getSignerInformation();
		PAdESCRLSource padesCRLSource = new PAdESCRLSource(timestampInfo.getDssDictionary(), null, signerInformation.getSignedAttributes());
		for (CRLBinary crlIdentifier : padesCRLSource.getCRLBinaryList()) {
			if (padesCRLSource.getRevocationOrigins(crlIdentifier).contains(RevocationOrigin.DSS_DICTIONARY) || 
					padesCRLSource.getRevocationOrigins(crlIdentifier).contains(RevocationOrigin.VRI_DICTIONARY)) {
				addReference(references, new TimestampedReference(crlIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		crlSource.add(padesCRLSource);
		
		PAdESOCSPSource padesOCSPSource = new PAdESOCSPSource(timestampInfo.getDssDictionary(), null, signerInformation.getSignedAttributes());
		for (OCSPResponseBinary ocspIdentifier : padesOCSPSource.getOCSPResponsesList()) {
			if (padesOCSPSource.getRevocationOrigins(ocspIdentifier).contains(RevocationOrigin.DSS_DICTIONARY) || 
					padesOCSPSource.getRevocationOrigins(ocspIdentifier).contains(RevocationOrigin.VRI_DICTIONARY)) {
				addReference(references, new TimestampedReference(ocspIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		ocspSource.add(padesOCSPSource);
	}

	@Override
	protected boolean isCompleteCertificateRef(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isAttributeCertificateRef(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isCompleteRevocationRef(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isAttributeRevocationRef(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isRefsOnlyTimestamp(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isSigAndRefsTimestamp(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isCertificateValues(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isRevocationValues(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	@Override
	protected boolean isArchiveTimestamp(CAdESAttribute unsignedAttribute) {
		// not applicable for PAdES
		return false;
	}

	private ArchiveTimestampType getArchiveTimestampType() {
		return getArchiveTimestampType(null);
	}
	
	@Override
	protected ArchiveTimestampType getArchiveTimestampType(CAdESAttribute unsignedAttribute) {
		return ArchiveTimestampType.PAdES;
	}
	
}
