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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESTimestampSource;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfSignatureDictionaryComparator;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampCertificateSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

@SuppressWarnings("serial")
public class PAdESTimestampSource extends CAdESTimestampSource {
	
	private final transient PdfSignatureRevision pdfSignatureRevision;
	
	private final transient List<PdfRevision> documentRevisions;
	
	public PAdESTimestampSource(final PAdESSignature signature, final List<PdfRevision> documentRevisions) {
		super(signature);
		Objects.requireNonNull(documentRevisions, "List of Document revisions must be provided!");
		this.pdfSignatureRevision = signature.getPdfRevision();
		// Reverse list to iterate in chronological order
		this.documentRevisions = reverseList(documentRevisions);
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
		PAdESTimestampDataBuilder padesTimestampDataBuilder = new PAdESTimestampDataBuilder(
				documentRevisions, signature.getSignerInformation(), signature.getDetachedContents());
		padesTimestampDataBuilder.setSignatureTimestamps(getSignatureTimestamps());
		return padesTimestampDataBuilder;
	}

	@Override
	protected void makeTimestampTokensFromUnsignedAttributes() {
		// Creates signature timestamp tokens only (from CAdESTimestampSource)
		super.makeTimestampTokensFromUnsignedAttributes();
		
		List<TimestampToken> cadesSignatureTimestamps = getSignatureTimestamps();
		final List<TimestampToken> timestampedTimestamps = new ArrayList<>(cadesSignatureTimestamps);
		final PdfSignatureDictionaryComparator revisionComparator = new PdfSignatureDictionaryComparator();
		
		// store all found references
		unsignedPropertiesReferences = new ArrayList<>();
		
		for (final PdfRevision pdfRevision : documentRevisions) {
			
			if (pdfRevision instanceof PdfDocTimestampRevision) {
				final PdfDocTimestampRevision timestampRevision = (PdfDocTimestampRevision) pdfRevision;
				
				final TimestampToken timestampToken = timestampRevision.getTimestampToken();
				if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
					timestampToken.getTimestampedReferences().addAll(getSignatureTimestampReferences());
					// timestamp covers inner signature, therefore it covers tokens included into the signature's SignedData
					timestampToken.getTimestampedReferences().addAll(getSignatureSignedDataReferences());
					
					cadesSignatureTimestamps.add(timestampToken);
					
				} else {
					// lists are separated in order to distinguish sources between different timestamps
					List<TimestampedReference> individualTimestampReferences = new ArrayList<>();
					
					// Archive TimeStamps
					timestampToken.setArchiveTimestampType(getArchiveTimestampType());
					
					if (Utils.isCollectionEmpty(cadesSignatureTimestamps)) {
						addReferences(individualTimestampReferences, getSignatureTimestampReferences());
					}
					addReferences(individualTimestampReferences, unsignedPropertiesReferences); // add all stored references from previous revisions
					addReferencesFromPreviousTimestamps(individualTimestampReferences, timestampedTimestamps);
					
					final TimestampCertificateSource timestampCertificateSource = timestampToken.getCertificateSource();
					certificateSource.add(timestampCertificateSource);
					
					addReferences(unsignedPropertiesReferences, createReferencesForCertificates(timestampCertificateSource.getCertificates()));
					// attach to a list of all references
					addReferences(unsignedPropertiesReferences, individualTimestampReferences);

					if (revisionComparator.compare(pdfSignatureRevision.getPdfSigDictInfo(), timestampRevision.getPdfSigDictInfo()) > 0) {
						// if a timestamp appears before the signature revision, do not create it
						continue;
					}
					
					// references embedded to timestamp's content are covered by outer timestamps
					addReferences(timestampToken.getTimestampedReferences(), individualTimestampReferences);
					
					getArchiveTimestamps().add(timestampToken);
					
				}
				
				populateSources(timestampToken);
				timestampedTimestamps.add(timestampToken);
				
			} else if (pdfRevision instanceof PdfDocDssRevision) {
				PdfDocDssRevision dssRevision = (PdfDocDssRevision) pdfRevision;
				
				// add all values present in dssRevision
				addReferencesForCertificates(unsignedPropertiesReferences, dssRevision);
				addReferencesFromRevocationData(unsignedPropertiesReferences, dssRevision);
				
			}
		}
	}
	
	/* Reverse list safely */
	private List<PdfRevision> reverseList(List<PdfRevision> pdfRevisions) {
		ArrayList<PdfRevision> listCopy = new ArrayList<>(pdfRevisions);
		Collections.reverse(listCopy);
		return listCopy;
	}

	private void addReferencesForCertificates(List<TimestampedReference> references, final PdfDocDssRevision dssRevision) {
		CommonCertificateSource dssRevisionCertificateSource = new CommonCertificateSource();
		
		Collection<CertificateToken> dssDictionaryCertValues = dssRevision.getDssDictionary().getCERTs().values();
		addReferences(references, createReferencesForCertificates(dssDictionaryCertValues));
		for (CertificateToken certificateToken : dssDictionaryCertValues) {
			dssRevisionCertificateSource.addCertificate(certificateToken);
		}
		
		if (Utils.isCollectionNotEmpty(dssRevision.getDssDictionary().getVRIs())) {
			for (PdfVRIDict vriDict : dssRevision.getDssDictionary().getVRIs()) {
				Collection<CertificateToken> vriDictionaryCertValues = vriDict.getCERTs().values();
				addReferences(references, createReferencesForCertificates(vriDictionaryCertValues));
				for (CertificateToken certificateToken : vriDictionaryCertValues) {
					dssRevisionCertificateSource.addCertificate(certificateToken);
				}
			}
		}
		
		certificateSource.add(dssRevisionCertificateSource);
	}

	/**
	 * This method adds references to retrieved revocation data.
	 * 
	 * @param references
	 */
	private void addReferencesFromRevocationData(List<TimestampedReference> references,
			final PdfDocDssRevision dssRevision) {
		PAdESCRLSource padesCRLSource = new PAdESCRLSource(dssRevision.getDssDictionary());
		for (EncapsulatedRevocationTokenIdentifier<CRL> token : padesCRLSource.getDSSDictionaryBinaries()) {
			addReference(references, token, TimestampedObjectType.REVOCATION);
		}
		for (EncapsulatedRevocationTokenIdentifier<CRL> token : padesCRLSource.getVRIDictionaryBinaries()) {
			addReference(references, token, TimestampedObjectType.REVOCATION);
		}
		crlSource.add(padesCRLSource);

		PAdESOCSPSource padesOCSPSource = new PAdESOCSPSource(dssRevision.getDssDictionary());
		for (EncapsulatedRevocationTokenIdentifier<OCSP> token : padesOCSPSource.getDSSDictionaryBinaries()) {
			addReference(references, token, TimestampedObjectType.REVOCATION);
		}
		for (EncapsulatedRevocationTokenIdentifier<OCSP> token : padesOCSPSource.getVRIDictionaryBinaries()) {
			addReference(references, token, TimestampedObjectType.REVOCATION);
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
	
	@Override
	protected List<AdvancedSignature> getCounterSignatures(CAdESAttribute unsignedAttribute) {
		// not supported in PAdES
		return Collections.emptyList();
	}
	
}
