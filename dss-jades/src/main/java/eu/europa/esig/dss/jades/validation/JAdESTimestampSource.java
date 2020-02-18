package eu.europa.esig.dss.jades.validation;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.EncapsulatedCertificateTokenIdentifier;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

public class JAdESTimestampSource extends AbstractTimestampSource<JAdESAttribute> {

	private final JAdESSignature signature;

	public JAdESTimestampSource(JAdESSignature signature, CertificatePool certPool) {
		super(signature);

		this.signature = signature;
	}

	@Override
	protected SignatureProperties<JAdESAttribute> getSignedSignatureProperties() {
		return new JAdESSignedProperties(signature.getJws().getHeaders());
	}

	@Override
	protected SignatureProperties<JAdESAttribute> getUnsignedSignatureProperties() {
		// not supported
		return null;
	}

	@Override
	protected boolean isContentTimestamp(JAdESAttribute signedAttribute) {
		return JAdESHeaderParameterNames.ADO_TST.equals(signedAttribute.getHeaderName());
	}

	@Override
	protected boolean isAllDataObjectsTimestamp(JAdESAttribute signedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isIndividualDataObjectsTimestamp(JAdESAttribute signedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isSignatureTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isCompleteCertificateRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isAttributeCertificateRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isCompleteRevocationRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isAttributeRevocationRef(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isRefsOnlyTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isSigAndRefsTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isCertificateValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isRevocationValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isArchiveTimestamp(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isTimeStampValidationData(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected TimestampToken makeTimestampToken(JAdESAttribute signatureAttribute, TimestampType timestampType,
			List<TimestampedReference> references) {
		// TODO implementation
		return null;
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(JAdESAttribute signedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Digest> getCertificateRefDigests(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Digest> getRevocationRefCRLDigests(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Digest> getRevocationRefOCSPDigests(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<EncapsulatedCertificateTokenIdentifier> getEncapsulatedCertificateIdentifiers(
			JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<CRLBinary> getEncapsulatedCRLIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<OCSPResponseBinary> getEncapsulatedOCSPIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected ArchiveTimestampType getArchiveTimestampType(JAdESAttribute unsignedAttribute) {
		// not supported
		return null;
	}

	@Override
	protected TimestampDataBuilder getTimestampDataBuilder() {
		return new JAdESTimestampDataBuilder(signature);
	}

}
