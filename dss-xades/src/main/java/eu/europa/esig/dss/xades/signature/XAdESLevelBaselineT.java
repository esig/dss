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
package eu.europa.esig.dss.xades.signature;

import static eu.europa.esig.dss.SignatureLevel.XAdES_BASELINE_T;
import static eu.europa.esig.dss.SignaturePackaging.ENVELOPED;
import static eu.europa.esig.dss.XAdESNamespaces.XAdES;
import static eu.europa.esig.dss.XAdESNamespaces.XAdES141;
import static eu.europa.esig.dss.x509.TimestampType.SIGNATURE_TIMESTAMP;
import static eu.europa.esig.dss.xades.ProfileParameters.Operation.SIGNING;
import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.TimestampParameters;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.ProfileParameters;
import eu.europa.esig.dss.xades.ProfileParameters.Operation;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import java.util.Arrays;

/**
 * -T profile of XAdES signature
 *
 */
public class XAdESLevelBaselineT extends ExtensionBuilder implements SignatureExtension<XAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelBaselineT.class);

	/*
	 * The object encapsulating the Time Stamp Protocol needed to create the level -T, of the signature
	 */
	protected TSPSource tspSource;

	/**
	 * The default constructor for XAdESLevelBaselineT.
	 */
	public XAdESLevelBaselineT(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
	}

	private void incorporateC14nMethod(final Element parentDom, final String signedInfoC14nMethod) {

		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element canonicalizationMethodDom = documentDom.createElementNS(XMLNS, DS_CANONICALIZATION_METHOD);
		canonicalizationMethodDom.setAttribute(ALGORITHM, signedInfoC14nMethod);
		parentDom.appendChild(canonicalizationMethodDom);
	}

	@Override
	public DSSDocument extendSignatures(final DSSDocument dssDocument, final XAdESSignatureParameters params) throws DSSException {

		if (dssDocument == null) {
			throw new NullPointerException();
		}
		if (this.tspSource == null) {
			throw new NullPointerException();
		}
		this.params = params;
		final ProfileParameters context = params.getContext();
		if (LOG.isInfoEnabled()) {
			LOG.info("====> Extending: {}", (dssDocument.getName() == null ? "IN MEMORY DOCUMENT" : dssDocument.getName()));
		}
		documentDom = DomUtils.buildDOM(dssDocument);

		final NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLNS, SIGNATURE);
		if (signatureNodeList.getLength() == 0) {
			throw new DSSException("There is no signature to extend!");
		}

		// In the case of the enveloped signature we have a specific treatment:<br>
		// we will just extend the signature that is being created (during creation process)
		String signatureId = null;
		final SignaturePackaging signaturePackaging = params.getSignaturePackaging();
		final Operation operationKind = context.getOperationKind();
		if (SIGNING.equals(operationKind) && ENVELOPED.equals(signaturePackaging)) {

			signatureId = params.getDeterministicId();
		}
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			currentSignatureDom = (Element) signatureNodeList.item(ii);
			final String currentSignatureId = currentSignatureDom.getAttribute(ID);
			if ((signatureId != null) && !signatureId.equals(currentSignatureId)) {

				continue;
			}
			xadesSignature = new XAdESSignature(currentSignatureDom, Arrays.asList(new XPathQueryHolder()), certificateVerifier.createValidationPool());
			xadesSignature.setDetachedContents(params.getDetachedContents());
			extendSignatureTag();
		}
		return createXmlDocument();
	}

	/**
	 * Extends the signature to a desired level. This method is overridden by other profiles.<br>
	 * For -T profile adds the SignatureTimeStamp element which contains a single HashDataInfo element that refers to
	 * the ds:SignatureValue element of the [XMLDSIG] signature. The timestamp token is obtained from TSP source.<br>
	 * Adds {@code <SignatureTimeStamp>} segment into {@code <UnsignedSignatureProperties>} element.
	 *
	 * @throws eu.europa.esig.dss.DSSException
	 */
	protected void extendSignatureTag() throws DSSException {

		assertExtendSignatureToTPossible();

		// We ensure that all XML segments needed for the construction of the extension -T are present.
		// If a segment does not exist then it is created.
		ensureUnsignedProperties();
		ensureUnsignedSignatureProperties();
		ensureSignedDataObjectProperties();
		assertSignatureValid(xadesSignature);
		
		Element levelBUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

		// The timestamp must be added only if there is no one or the extension -T level is being created
		if (!xadesSignature.hasTProfile() || XAdES_BASELINE_T.equals(params.getSignatureLevel())) {

			final TimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			final String canonicalizationMethod = signatureTimestampParameters.getCanonicalizationMethod();
			final byte[] canonicalisedValue = xadesSignature.getSignatureTimestampData(null, canonicalizationMethod);
			final DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
			final byte[] digestValue = DSSUtils.digest(timestampDigestAlgorithm, canonicalisedValue);
			createXAdESTimeStampType(SIGNATURE_TIMESTAMP, canonicalizationMethod, digestValue);
			
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelBUnsignedProperties);
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToTPossible() {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (XAdES_BASELINE_T.equals(signatureLevel) && (xadesSignature.hasLTProfile() || xadesSignature.hasLTAProfile())) {
			final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
			throw new DSSException(String.format(exceptionMessage, "XAdES LT"));
		}
	}

	/**
	 * Sets the TSP source to be used when extending the digital signature
	 *
	 * @param tspSource
	 *            the tspSource to set
	 */
	public void setTspSource(final TSPSource tspSource) {

		this.tspSource = tspSource;
	}

	/**
	 * This method incorporates all certificates passed as parameter :
	 * 
	 * <pre>
	 * {@code
	 * 	<xades:CertificateValues>
	 *		<xades:EncapsulatedX509Certificate>MIIC9TC...</xades:EncapsulatedX509Certificate>
	 *		...
	 * 	</xades:CertificateValues>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param validationContext
	 *            the validation context with all certificates
	 */
	protected Element incorporateCertificateValues(final Element parentDom, final ValidationContext validationContext) {

		Element certificateValuesDom = null;
		final Set<CertificateToken> toIncludeCertificates = xadesSignature.getCertificatesForInclusion(validationContext);
		if (!toIncludeCertificates.isEmpty()) {

			certificateValuesDom = DomUtils.addElement(documentDom, parentDom, XAdES, XADES_CERTIFICATE_VALUES);

			CertificateSource trustedCertSource = certificateVerifier.getTrustedCertSource();

			final boolean trustAnchorBPPolicy = params.bLevel().isTrustAnchorBPPolicy();
			boolean trustAnchorIncluded = false;
			for (final CertificateToken certificateToken : toIncludeCertificates) {
				if (trustAnchorBPPolicy && (trustedCertSource != null)) {
					if (!trustedCertSource.get(certificateToken.getSubjectX500Principal()).isEmpty()) {
						trustAnchorIncluded = true;
					}
				}
				final byte[] bytes = certificateToken.getEncoded();
				final String base64EncodeCertificate = Utils.toBase64(bytes);
				DomUtils.addTextElement(documentDom, certificateValuesDom, XAdES, XADES_ENCAPSULATED_X509_CERTIFICATE, base64EncodeCertificate);
			}
			if (trustAnchorBPPolicy && !trustAnchorIncluded) {
				LOG.warn("The trust anchor is missing but its inclusion is required by the signature policy!");
			}
		}
		return certificateValuesDom;
	}

	/**
	 * This method incorporates revocation values.
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:RevocationValues>
	 * 	}
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param validationContext
	 *            the validation context with the revocation data
	 */
	protected Element incorporateRevocationValues(final Element parentDom, final ValidationContext validationContext) {
		Element revocationValuesDom = null;
		final DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusion = xadesSignature.getRevocationDataForInclusion(validationContext);
		if (!revocationsForInclusion.isEmpty()) {

			revocationValuesDom = DomUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:RevocationValues");

			incorporateCrlTokens(revocationValuesDom, revocationsForInclusion.crlTokens);
			incorporateOcspTokens(revocationValuesDom, revocationsForInclusion.ocspTokens);
		}
		return revocationValuesDom;
	}

	/**
	 * This method incorporates the CRLValues :
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:CRLValues>
	 * 			<xades:EncapsulatedCRLValue>...</xades:EncapsulatedCRLValue>
	 * 			...
	 * 		</xades:CRLValues>
	 * 	}
	 * </pre>
	 * 
	 * @param parentDom
	 *            the parent element
	 * @param crlTokens
	 *            the list of CRL Tokens to be added
	 */
	private void incorporateCrlTokens(final Element parentDom, final List<CRLToken> crlTokens) {
		if (crlTokens.isEmpty()) {
			return;
		}
		final Element crlValuesDom = DomUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:CRLValues");

		for (final RevocationToken revocationToken : crlTokens) {
			final byte[] encodedCRL = revocationToken.getEncoded();
			final String base64EncodedCRL = Utils.toBase64(encodedCRL);
			DomUtils.addTextElement(documentDom, crlValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedCRLValue", base64EncodedCRL);
		}
	}

	/**
	 * This method incorporates the OCSP responses :
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:OCSPValues>
	 * 			<xades:EncapsulatedOCSPValue>...</xades:EncapsulatedOCSPValue>
	 * 			...
	 * 		</xades:OCSPValues>
	 * 	}
	 * </pre>
	 * 
	 * @param parentDom
	 *            the parent element
	 * @param ocspTokens
	 *            the list of OCSP Tokens to be added
	 */
	private void incorporateOcspTokens(Element parentDom, final List<OCSPToken> ocspTokens) {
		if (ocspTokens.isEmpty()) {
			return;
		}
		final Element ocspValuesDom = DomUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:OCSPValues");

		for (final RevocationToken revocationToken : ocspTokens) {
			final byte[] encodedOCSP = revocationToken.getEncoded();
			final String base64EncodedOCSP = Utils.toBase64(encodedOCSP);
			DomUtils.addTextElement(documentDom, ocspValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedOCSPValue", base64EncodedOCSP);
		}
	}
	
	/**
	 * This method incorporates all certificates passed as parameter, as well as adds missing indents if the parameter is specified
	 * 
	 * <pre>
	 * {@code
	 * 	<xades:CertificateValues>
	 *		<xades:EncapsulatedX509Certificate>MIIC9TC...</xades:EncapsulatedX509Certificate>
	 *		...
	 * 	</xades:CertificateValues>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param validationContext
	 *            the validation context with all certificates
	 * @param indent
	 *            {@link String} to add between elements (if not NULL)
	 */
	protected void incorporateCertificateValues(final Element parentDom, final ValidationContext validationContext, String indent) {
		Element certificatesDom = incorporateCertificateValues(parentDom, validationContext);
		if (certificatesDom != null && indent != null) {
			DomUtils.setTextNode(documentDom, unsignedSignaturePropertiesDom, indent);
			DSSXMLUtils.indentAndReplace(documentDom, certificatesDom);
		}
	}


	/**
	 * This method incorporates revocation values, as well as adds missing indents if the parameter is specified:
	 * 
	 * <pre>
	 * 	{@code
	 * 		<xades:RevocationValues>
	 * 	}
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param validationContext
	 *            the validation context with the revocation data
	 * @param indent
	 *            {@link String} to add between elements (if not NULL)
	 */
	protected void incorporateRevocationValues(final Element parentDom, final ValidationContext validationContext, String indent) {
		Element revocationDom = incorporateRevocationValues(parentDom, validationContext);
		if (revocationDom != null && indent != null) {
			DomUtils.setTextNode(documentDom, unsignedSignaturePropertiesDom, indent);
			DSSXMLUtils.indentAndReplace(documentDom, revocationDom);
		}
	}

	/**
	 * Creates any XAdES TimeStamp object representation. The timestamp token is obtained from TSP source
	 *
	 * @param timestampType
	 *            {@code TimestampType}
	 * @param timestampC14nMethod
	 *            canonicalization method
	 * @param digestValue
	 *            array of {@code byte} representing the digest to timestamp
	 * @throws DSSException
	 *             in case of any error
	 */
	protected void createXAdESTimeStampType(final TimestampType timestampType, final String timestampC14nMethod, final byte[] digestValue) throws DSSException {

		Element timeStampDom = null;
		final TimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
		DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
		switch (timestampType) {

		case SIGNATURE_TIMESTAMP:
			// <xades:SignatureTimeStamp Id="time-stamp-1dee38c4-8388-40d1-8880-9eeda853fe60">
			timeStampDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES, XADES_SIGNATURE_TIME_STAMP);
			break;
		case VALIDATION_DATA_TIMESTAMP:
			// <xades:SigAndRefsTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
			if (params.isEn319132() && !isOldGeneration(params.getSignatureLevel())) {
				timeStampDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES, XADES_SIG_AND_REFS_TIME_STAMP_V2);
			} else {
				timeStampDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES, XADES_SIG_AND_REFS_TIME_STAMP);
			}
			break;
		case ARCHIVE_TIMESTAMP:
			// <xades141:ArchiveTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
			timeStampDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES141, XADES141_ARCHIVE_TIME_STAMP);
			timestampDigestAlgorithm = params.getArchiveTimestampParameters().getDigestAlgorithm();
			break;
		default:
			// Content timestamps need to be generated before the signature itself
			throw new DSSException("Unsupported timestamp type : " + timestampType);
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("Timestamp generation: {} / {} / {}", timestampDigestAlgorithm.getName(), timestampC14nMethod,
					Utils.toBase64(digestValue));
		}
		final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digestValue);
		final String base64EncodedTimeStampToken = Utils.toBase64(DSSASN1Utils.getDEREncoded(timeStampToken));

		final String timestampId = UUID.randomUUID().toString();
		timeStampDom.setAttribute(ID, "TS-" + timestampId);

		// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
		incorporateC14nMethod(timeStampDom, timestampC14nMethod);

		// <xades:EncapsulatedTimeStamp Id="time-stamp-token-6a150419-caab-4615-9a0b-6e239596643a">MIAGCSqGSIb3DQEH
		final Element encapsulatedTimeStampDom = DomUtils.addElement(documentDom, timeStampDom, XAdES, XADES_ENCAPSULATED_TIME_STAMP);
		encapsulatedTimeStampDom.setAttribute(ID, "ETS-" + timestampId);
		DomUtils.setTextNode(documentDom, encapsulatedTimeStampDom, base64EncodedTimeStampToken);
	}

	private boolean isOldGeneration(SignatureLevel signatureLevel) {
		return SignatureLevel.XAdES_X.equals(signatureLevel) || SignatureLevel.XAdES_XL.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

}
