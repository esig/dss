package eu.europa.esig.dss.jades.validation;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

public class JAdESTimestampSource extends AbstractTimestampSource<JAdESAttribute> {

	private final JAdESSignature signature;

	public JAdESTimestampSource(JAdESSignature signature) {
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
	protected boolean isAttrAuthoritiesCertValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected boolean isAttributeRevocationValues(JAdESAttribute unsignedAttribute) {
		// not supported
		return false;
	}

	@Override
	protected List<CertificateRef> getCertificateRefs(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<CRLRef> getCRLRefs(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<OCSPRef> getOCSPRefs(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Identifier> getEncapsulatedCertificateIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<TimestampedReference> getArchiveTimestampOtherReferences(TimestampToken timestampToken) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Identifier> getEncapsulatedCRLIdentifiers(JAdESAttribute unsignedAttribute) {
		// not supported
		return Collections.emptyList();
	}

	@Override
	protected List<Identifier> getEncapsulatedOCSPIdentifiers(JAdESAttribute unsignedAttribute) {
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
