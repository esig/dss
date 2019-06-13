package eu.europa.esig.dss.xades.validation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.SignatureScope;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.SignatureProperties;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import eu.europa.esig.dss.x509.ArchiveTimestampType;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.EncapsulatedCertificateTokenIdentifier;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.TimestampLocation;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.CRLBinaryIdentifier;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPResponseIdentifier;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

public class XAdESTimestampSource extends AbstractTimestampSource<XAdESAttribute> {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESTimestampSource.class);
	
	private final Element signatureElement;
	private final XPathQueryHolder xPathQueryHolder;
	
	private List<Reference> references;
	private List<ReferenceValidation> referenceValidations;

	/**
	 * Cached list of the Signing Certificate Timestamp References.
	 */
	private List<TimestampedReference> signingCertificateTimestampReferences;
	
	private XAdESTimestampDataBuilder timestampDataBuilder;
	
	public XAdESTimestampSource(final XAdESSignature signature, final Element signatureElement, 
			final XPathQueryHolder xPathQueryHolder, final CertificatePool certificatePool) {
		super(signature);
		this.references = signature.getReferences();
		this.referenceValidations = signature.getReferenceValidations();
		this.signatureElement = signatureElement;
		this.xPathQueryHolder = xPathQueryHolder;
		this.certificatePool = certificatePool;
	}

	@Override
	protected SignatureProperties<XAdESAttribute> getSignedSignatureProperties() {
		return XAdESSignedDataObjectProperties.build(signatureElement, xPathQueryHolder);
	}

	@Override
	protected SignatureProperties<XAdESAttribute> getUnsignedSignatureProperties() {
		return XAdESUnsignedSigProperties.build(signatureElement, xPathQueryHolder);
	}

	@Override
	protected XAdESTimestampDataBuilder getTimestampDataBuilder() {
		if (timestampDataBuilder == null) {
			timestampDataBuilder = new XAdESTimestampDataBuilder(signatureElement, references, xPathQueryHolder);
		}
		return timestampDataBuilder;
	}
	
	/**
	 * Returns concatenated data for a SignatureTimestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return byte array
	 */
	public byte[] getSignatureTimestampData(String canonicalizationMethod) {
		return timestampDataBuilder.getSignatureTimestampData(canonicalizationMethod);
	}
	
	/**
	 * Returns concatenated data for a SigAndRefsTimestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return byte array
	 */
	public byte[] getTimestampX1Data(String canonicalizationMethod) {
		return timestampDataBuilder.getTimestampX1Data(canonicalizationMethod);
	}
	
	/**
	 * Returns concatenated data for a RefsOnlyTimestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return byte array
	 */
	public byte[] getTimestampX2Data(String canonicalizationMethod) {
		return timestampDataBuilder.getTimestampX2Data(canonicalizationMethod);
	}
	
	/**
	 * Returns concatenated data for an ArchiveTimestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return byte array
	 */
	public byte[] getArchiveTimestampData(String canonicalizationMethod) {
		return timestampDataBuilder.getArchiveTimestampData(canonicalizationMethod);
	}

	@Override
	protected boolean isContentTimestamp(XAdESAttribute signedAttribute) {
		// Not applicable for XAdES
		return false;
	}

	@Override
	protected boolean isAllDataObjectsTimestamp(XAdESAttribute signedAttribute) {
		return XPathQueryHolder.XMLE_ALL_DATA_OBJECTS_TIME_STAMP.equals(signedAttribute.getName());
	}

	@Override
	protected boolean isIndividualDataObjectsTimestamp(XAdESAttribute signedAttribute) {
		return XPathQueryHolder.XMLE_INDIVIDUAL_DATA_OBJECTS_TIME_STAMP.equals(signedAttribute.getName());
	}

	@Override
	protected boolean isSignatureTimestamp(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_SIGNATURE_TIME_STAMP.equals(unsignedAttribute.getName());
	}

	@Override
	protected boolean isCompleteCertificateRef(XAdESAttribute unsignedAttribute) {
		String localName = unsignedAttribute.getName();
		return XPathQueryHolder.XMLE_COMPLETE_CERTIFICATE_REFS.equals(localName) || XPathQueryHolder.XMLE_COMPLETE_CERTIFICATE_REFS_V2.equals(localName);
	}

	@Override
	protected boolean isAttributeCertificateRef(XAdESAttribute unsignedAttribute) {
		String localName = unsignedAttribute.getName();
		return XPathQueryHolder.XMLE_ATTRIBUTE_CERTIFICATE_REFS.equals(localName) || XPathQueryHolder.XMLE_ATTRIBUTE_CERTIFICATE_REFS_V2.equals(localName);
	}

	@Override
	protected boolean isCompleteRevocationRef(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_COMPLETE_REVOCATION_REFS.equals(unsignedAttribute.getName());
	}

	@Override
	protected boolean isAttributeRevocationRef(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_ATTRIBUTE_REVOCATION_REFS.equals(unsignedAttribute.getName());
	}

	@Override
	protected boolean isRefsOnlyTimestamp(XAdESAttribute unsignedAttribute) {
		String localName = unsignedAttribute.getName();
		return XPathQueryHolder.XMLE_REFS_ONLY_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_REFS_ONLY_TIME_STAMP_V2.equals(localName);
	}

	@Override
	protected boolean isSigAndRefsTimestamp(XAdESAttribute unsignedAttribute) {
		String localName = unsignedAttribute.getName();
		return XPathQueryHolder.XMLE_SIG_AND_REFS_TIME_STAMP.equals(localName) || XPathQueryHolder.XMLE_SIG_AND_REFS_TIME_STAMP_V2.equals(localName);
	}

	@Override
	protected boolean isCertificateValues(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_CERTIFICATE_VALUES.equals(unsignedAttribute.getName());
	}

	@Override
	protected boolean isRevocationValues(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_REVOCATION_VALUES.equals(unsignedAttribute.getName());
	}

	@Override
	protected boolean isArchiveTimestamp(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(unsignedAttribute.getName());
	}

	@Override
	protected boolean isTimeStampValidationData(XAdESAttribute unsignedAttribute) {
		return XPathQueryHolder.XMLE_TIME_STAMP_VALIDATION_DATA.equals(unsignedAttribute.getName());
	}

	@Override
	protected TimestampToken makeTimestampToken(XAdESAttribute unsignedAttribute, TimestampType timestampType, 
			List<TimestampedReference> references) {

		final Element timestampTokenNode = unsignedAttribute.findElement(xPathQueryHolder.XPATH__ENCAPSULATED_TIMESTAMP);
		if (timestampTokenNode == null) {
			LOG.warn("The timestamp {} cannot be extracted from the signature!", timestampType.name());
			return null;
		}
		
		TimestampToken timestampToken = null;
		try {
			timestampToken = new TimestampToken(Utils.fromBase64(timestampTokenNode.getTextContent()), timestampType, 
					certificatePool, references, TimestampLocation.XAdES);
		} catch (Exception e) {
			LOG.warn("Unable to build timestamp object '" + timestampTokenNode.getTextContent() + "' : ", e);
			return null;
		}
		
		timestampToken.setHashCode(unsignedAttribute.hashCode());
		timestampToken.setCanonicalizationMethod(unsignedAttribute.getTimestampCanonicalizationMethod());
		timestampToken.setTimestampIncludes(unsignedAttribute.getTimestampIncludedReferences());
		
		return timestampToken;
		
	}

	@Override
	protected List<TimestampedReference> getIndividualContentTimestampedReferences(XAdESAttribute signedAttribute) {
		List<TimestampInclude> includes = signedAttribute.getTimestampIncludedReferences();
		List<TimestampedReference> timestampReferences = new ArrayList<TimestampedReference>();
		for (Reference reference : references) {
			if (isContentTimestampedReference(reference, includes)) {
				for (SignatureScope signatureScope : signatureScopes) {
					if (Utils.endsWithIgnoreCase(reference.getURI(), signatureScope.getName())) {
						timestampReferences.add(new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
					}
				}
			}
		}
		return timestampReferences;
	}
	
	private boolean isContentTimestampedReference(Reference reference, List<TimestampInclude> includes) {
		for (TimestampInclude timestampInclude : includes) {
			if (reference.getId().equals(timestampInclude.getURI())) {
				return true;
			}
		}
		return false;
	}
	
	@Override
	protected List<TimestampedReference> getSigningCertificateTimestampReferences() {
		if (signingCertificateTimestampReferences == null) {
			signingCertificateTimestampReferences = super.getSigningCertificateTimestampReferences();

			if (isKeyInfoCovered()) {
				List<CertificateToken> keyInfoCerts = certificateSource.getKeyInfoCertificates();
				for (CertificateToken certificate : keyInfoCerts) {
					signingCertificateTimestampReferences.add(new TimestampedReference(certificate.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
				}
			}
		}
		return signingCertificateTimestampReferences;
	}

	private boolean isKeyInfoCovered() {
		if (Utils.isCollectionNotEmpty(referenceValidations)) {
			for (ReferenceValidation referenceValidation : referenceValidations) {
				if (DigestMatcherType.KEY_INFO.equals(referenceValidation.getType()) && referenceValidation.isFound() && referenceValidation.isIntact()) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	protected List<Digest> getCertificateRefDigests(XAdESAttribute unsignedAttribute) {
		List<Digest> digests = new ArrayList<Digest>();
		NodeList nodeList = unsignedAttribute.getNodeList(xPathQueryHolder.XPATH__CERTIFICATE_REFS);
		for (int ii = 0; ii < nodeList.getLength(); ii++) {
			Element certElement = (Element) nodeList.item(ii);
			Digest certDigest = XAdESUtils.getCertDigest(certElement, xPathQueryHolder);
			if (certDigest != null) {
				digests.add(certDigest);
			}
		}
		return digests;
	}

	@Override
	protected List<Digest> getRevocationRefCRLDigests(XAdESAttribute unsignedAttribute) {
		List<Digest> crlRefDigests = new ArrayList<Digest>();
		NodeList crlRefs = unsignedAttribute.getNodeList(xPathQueryHolder.XPATH__CRLREFS);
		for (int ii = 0; ii < crlRefs.getLength(); ii++) {
			Element crlRef = (Element) crlRefs.item(ii);
			Digest digest = XAdESUtils.getRevocationDigest(crlRef, xPathQueryHolder);
			if (digest != null) {
				crlRefDigests.add(digest);
			}
		}
		return crlRefDigests;
	}

	@Override
	protected List<Digest> getRevocationRefOCSPDigests(XAdESAttribute unsignedAttribute) {
		List<Digest> ocspRefDigests = new ArrayList<Digest>();
		NodeList ocspRefs = unsignedAttribute.getNodeList(xPathQueryHolder.XPATH__OCSPREFS);
		for (int ii = 0; ii < ocspRefs.getLength(); ii++) {
			Element ocspRef = (Element) ocspRefs.item(ii);
			Digest digest = XAdESUtils.getRevocationDigest(ocspRef, xPathQueryHolder);
			if (digest != null) {
				ocspRefDigests.add(digest);
			}
		}
		return ocspRefDigests;
	}

	@Override
	protected List<EncapsulatedCertificateTokenIdentifier> getEncapsulatedCertificateIdentifiers(XAdESAttribute unsignedAttribute) {
		List<EncapsulatedCertificateTokenIdentifier> certificateIdentifiers = new ArrayList<EncapsulatedCertificateTokenIdentifier>();
		NodeList encapsulatedNodes = unsignedAttribute.getNodeList(xPathQueryHolder.XPATH___ENCAPSULATED_X509_CERT);
		for (int ii = 0; ii < encapsulatedNodes.getLength(); ii++) {
			Element element = (Element) encapsulatedNodes.item(ii);
			byte[] binaries = getEncapsulatedTokenBinaries(element);
			EncapsulatedCertificateTokenIdentifier tokenIdentifier = new EncapsulatedCertificateTokenIdentifier(binaries);
			certificateIdentifiers.add(tokenIdentifier);
		}
		return certificateIdentifiers;
	}

	@Override
	protected List<CRLBinaryIdentifier> getEncapsulatedCRLIdentifiers(XAdESAttribute unsignedAttribute) {
		List<CRLBinaryIdentifier> crlIdentifiers = new ArrayList<CRLBinaryIdentifier>();
		NodeList encapsulatedNodes = unsignedAttribute.getNodeList(xPathQueryHolder.XPATH___ENCAPSULATED_CRL_VALUES);
		for (int ii = 0; ii < encapsulatedNodes.getLength(); ii++) {
			Element element = (Element) encapsulatedNodes.item(ii);
			byte[] binaries = getEncapsulatedTokenBinaries(element);
			CRLBinaryIdentifier tokenIdentifier;
			if (isRevocationValues(unsignedAttribute)) {
				tokenIdentifier = CRLBinaryIdentifier.build(binaries, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
			} else {
				// timestamp validation data
				tokenIdentifier = CRLBinaryIdentifier.build(binaries, RevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES);
			}
			crlIdentifiers.add(tokenIdentifier);
		}
		return crlIdentifiers;
	}

	@Override
	protected List<OCSPResponseIdentifier> getEncapsulatedOCSPIdentifiers(XAdESAttribute unsignedAttribute) {
		List<OCSPResponseIdentifier> crlIdentifiers = new ArrayList<OCSPResponseIdentifier>();
		NodeList encapsulatedNodes = unsignedAttribute.getNodeList(xPathQueryHolder.XPATH___ENCAPSULATED_CRL_VALUES);
		for (int ii = 0; ii < encapsulatedNodes.getLength(); ii++) {
			Element element = (Element) encapsulatedNodes.item(ii);
			byte[] binaries = getEncapsulatedTokenBinaries(element);
			try {
				BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPFromBinaries(binaries);
				OCSPResponseIdentifier tokenIdentifier;
				if (isRevocationValues(unsignedAttribute)) {
					tokenIdentifier = OCSPResponseIdentifier.build(basicOCSPResp, RevocationOrigin.INTERNAL_REVOCATION_VALUES);
				} else {
					// timestamp validation data
					tokenIdentifier = OCSPResponseIdentifier.build(basicOCSPResp, RevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES);
				}
				crlIdentifiers.add(tokenIdentifier);
			} catch (IOException e) {
				LOG.error("Cannot read encapsulated OCSP response. Reason: {}", e.getMessage());
			}
		}
		return crlIdentifiers;
	}
	
	/**
	 * Returns encapsulated byte array from the given {@code encapsulatedElement}
	 * @param encapsulatedElement {@link Element} to get binaries from
	 * @return byte array
	 */
	private byte[] getEncapsulatedTokenBinaries(Element encapsulatedElement) {
		if (encapsulatedElement.hasChildNodes()) {
			Node firstChild = encapsulatedElement.getFirstChild();
			if (Node.TEXT_NODE == firstChild.getNodeType()) {
				String base64String = firstChild.getTextContent();
				if (Utils.isBase64Encoded(base64String)) {
					return Utils.fromBase64(base64String);
				}
			}
		}
		throw new DSSException(String.format("Cannot create the token reference. "
				+ "The element with local name [%s] must contain an encapsulated base64 token value!", encapsulatedElement.getLocalName()));
	}

	@Override
	protected ArchiveTimestampType getArchiveTimestampType(XAdESAttribute unsignedAttribute) {
		if (XAdESNamespaces.XAdES141.equals(unsignedAttribute.getNamespace())) {
			return ArchiveTimestampType.XAdES_141;
		}
		return ArchiveTimestampType.XAdES;
	}

}
