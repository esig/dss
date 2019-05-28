package eu.europa.esig.dss.pades.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESTimestampSource;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.CRLBinaryIdentifier;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseIdentifier;

public class PAdESTimestampSource extends CAdESTimestampSource {
	
	private final PdfSignatureInfo pdfSignatureInfo;
	
	public PAdESTimestampSource(final SignerInformation signerInformation, final CertificatePool certificatePool, 
			final PdfSignatureInfo pdfSignatureInfo) {
		super(signerInformation, certificatePool);
		this.pdfSignatureInfo = pdfSignatureInfo;
	}
	
	@Override
	public List<TimestampToken> getDocumentTimestamps() {
		if (documentTimestamps == null) {
			makeTimestampTokens();
		}
		return documentTimestamps;
	}

	@Override
	protected void makeTimestampTokens() {
		// Creates signature timestamp tokens only (from CAdESTimestampSource)
		super.makeTimestampTokens();
		
		documentTimestamps = new ArrayList<TimestampToken>();
		
		final List<TimestampToken> timestampedTimestamps = new ArrayList<TimestampToken>(signatureTimestamps);
		
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {
			
			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {
				final PdfDocTimestampInfo timestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				// Timestamp needs to be cloned in order to avoid shared instances among sources
				final TimestampToken timestampToken = timestampInfo.getTimestampToken().clone();
				if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
					timestampToken.setTimestampedReferences(getSignatureTimestampReferences());
					signatureTimestamps.add(timestampToken);
					
				} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
					List<TimestampedReference> references = new ArrayList<TimestampedReference>();
					if (Utils.isCollectionEmpty(signatureTimestamps)) {
						references = getSignatureTimestampReferences();
					}
					addReferencesForPreviousTimestamps(references, timestampedTimestamps);
					addReferencesForCertificates(references);
					addReferencesFromRevocationData(references);
					timestampToken.setTimestampedReferences(references);
					archiveTimestamps.add(timestampToken);
					
				} else {
					documentTimestamps.add(timestampToken);
					
				}
				
				timestampedTimestamps.add(timestampToken);
			}
		}
	}

	protected void addReferencesForCertificates(List<TimestampedReference> references) {
		List<CertificateToken> dssDictionaryCertValues = certificateSource.getDSSDictionaryCertValues();
		for (CertificateToken certificate : dssDictionaryCertValues) {
			addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		List<CertificateToken> vriDictionaryCertValues = certificateSource.getVRIDictionaryCertValues();
		for (CertificateToken certificate : vriDictionaryCertValues) {
			addReference(references, new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
	}

	/**
	 * This method adds references to retrieved revocation data.
	 * 
	 * @param references
	 */
	protected void addReferencesFromRevocationData(List<TimestampedReference> references) {
		for (CRLBinaryIdentifier crlIdentifier : crlSource.getAllCRLIdentifiers()) {
			if (crlIdentifier.getOrigins().contains(RevocationOrigin.INTERNAL_DSS) || crlIdentifier.getOrigins().contains(RevocationOrigin.INTERNAL_VRI)) {
				addReference(references, new TimestampedReference(crlIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
		for (OCSPResponseIdentifier ocspIdentifier : ocspSource.getAllOCSPIdentifiers()) {
			if (ocspIdentifier.getOrigins().contains(RevocationOrigin.INTERNAL_DSS) || ocspIdentifier.getOrigins().contains(RevocationOrigin.INTERNAL_VRI)) {
				addReference(references, new TimestampedReference(ocspIdentifier.asXmlId(), TimestampedObjectType.REVOCATION));
			}
		}
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
	
}
