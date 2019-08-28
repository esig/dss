package eu.europa.esig.dss.pades.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESTimestampSource;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

@SuppressWarnings("serial")
public class PAdESTimestampSource extends CAdESTimestampSource {
	
	private transient final PdfSignatureInfo pdfSignatureInfo;
	
	public PAdESTimestampSource(final PAdESSignature signature, final CertificatePool certificatePool) {
		super(signature, certificatePool);
		this.pdfSignatureInfo = signature.getPdfSignatureInfo();
	}
	
	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		if (getSignatureTimestamps() == null || getArchiveTimestamps() == null) {
			createAndValidate();
		}
		List<TimestampToken> documentTimestamps = new ArrayList<TimestampToken>();
		documentTimestamps.addAll(getSignatureTimestamps());
		documentTimestamps.addAll(getArchiveTimestamps());
		return documentTimestamps;
	}

	@Override
	protected PAdESTimestampDataBuilder getTimestampDataBuilder() {
		PAdESTimestampDataBuilder padesTimestampDataBuilder = new PAdESTimestampDataBuilder(pdfSignatureInfo, signerInformation, detachedDocuments);
		padesTimestampDataBuilder.setSignatureTimestamps(getSignatureTimestamps());
		return padesTimestampDataBuilder;
	}

	@Override
	protected void makeTimestampTokens() {
		// Creates signature timestamp tokens only (from CAdESTimestampSource)
		super.makeTimestampTokens();
		
		final List<TimestampToken> timestampedTimestamps = new ArrayList<TimestampToken>(getSignatureTimestamps());
		
		// contains KeyInfo certificates embedded to the timestamp's content
		final List<CertificateToken> cmsContentCertificates = new ArrayList<CertificateToken>();
		
		final List<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {
			
			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {
				final PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				// Timestamp needs to be cloned in order to avoid shared instances among sources
				final TimestampToken timestampToken = new TimestampToken(timestampInfo.getTimestampToken());
				// clear timestamped references list in order to avoid data mixing between different signatures
				timestampToken.getTimestampedReferences().clear();
				if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
					timestampToken.getTimestampedReferences().addAll(getSignatureTimestampReferences());
					getSignatureTimestamps().add(timestampToken);
					
				} else {
					// Archive TimeStamps
					timestampToken.setArchiveTimestampType(getArchiveTimestampType());
					
					List<TimestampedReference> references = new ArrayList<TimestampedReference>();
					if (Utils.isCollectionEmpty(getSignatureTimestamps())) {
						references = getSignatureTimestampReferences();
					}
					addReferencesForPreviousTimestamps(references, timestampedTimestamps);
					
					// extract timestamped references from the timestamped DSS Dictionary
					final PdfDssDict coveredDSSDictionary = timestampInfo.getDssDictionary();
					final PAdESCertificateSource padesCertificateSource = new PAdESCertificateSource(
							coveredDSSDictionary, timestampInfo.getCMSSignedData(), certificatePool);

					addReferences(references, createReferencesForCertificates(cmsContentCertificates));
					addReferencesForCertificates(references, padesCertificateSource);
					addReferencesFromRevocationData(references, coveredDSSDictionary);
					
					// references embedded to timestamp's content are covered by outer timestamps
					cmsContentCertificates.addAll(getCMSContentReferences(padesCertificateSource));
					
					timestampToken.getTimestampedReferences().addAll(references);
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
	private void addReferencesFromRevocationData(List<TimestampedReference> references, final PdfDssDict dssDictionary) {
		PAdESCRLSource padesCRLSource = new PAdESCRLSource(dssDictionary);
		for (CRLBinary crlIdentifier : padesCRLSource.getCRLBinaryList()) {
			if (padesCRLSource.getRevocationOrigins(crlIdentifier).contains(RevocationOrigin.DSS_DICTIONARY) || 
					padesCRLSource.getRevocationOrigins(crlIdentifier).contains(RevocationOrigin.VRI_DICTIONARY)) {
				addReference(references, new TimestampedReference(crlIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		crlSource.addAll(padesCRLSource);
		
		PAdESOCSPSource padesOCSPSource = new PAdESOCSPSource(dssDictionary);
		for (OCSPResponseBinary ocspIdentifier : padesOCSPSource.getOCSPResponsesList()) {
			if (padesOCSPSource.getRevocationOrigins(ocspIdentifier).contains(RevocationOrigin.DSS_DICTIONARY) || 
					padesOCSPSource.getRevocationOrigins(ocspIdentifier).contains(RevocationOrigin.VRI_DICTIONARY)) {
				addReference(references, new TimestampedReference(ocspIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		ocspSource.addAll(padesOCSPSource);
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
