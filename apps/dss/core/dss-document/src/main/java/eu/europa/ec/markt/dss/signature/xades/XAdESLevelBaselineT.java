/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.xades;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.ProfileParameters.Operation;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.ValidationContext;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

import static eu.europa.ec.markt.dss.XAdESNamespaces.XAdES;
import static eu.europa.ec.markt.dss.XAdESNamespaces.XAdES141;
import static eu.europa.ec.markt.dss.signature.ProfileParameters.Operation.SIGNING;
import static eu.europa.ec.markt.dss.signature.SignatureLevel.XAdES_BASELINE_T;
import static eu.europa.ec.markt.dss.signature.SignaturePackaging.ENVELOPED;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.SIGNATURE_TIMESTAMP;
import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

/**
 * -T profile of XAdES signature
 *
 * @version $Revision$ - $Date$
 */

public class XAdESLevelBaselineT extends ExtensionBuilder implements XAdESSignatureExtension {

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

		//<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element canonicalizationMethodDom = documentDom.createElementNS(XMLNS, DS_CANONICALIZATION_METHOD);
		canonicalizationMethodDom.setAttribute(ALGORITHM, signedInfoC14nMethod);
		parentDom.appendChild(canonicalizationMethodDom);
	}

	@Override
	public InMemoryDocument extendSignatures(final DSSDocument dssDocument, final SignatureParameters params) throws DSSException {

		if (dssDocument == null) {
			throw new DSSNullException(DSSDocument.class);
		}
		if (this.tspSource == null) {
			throw new DSSNullException(TSPSource.class);
		}
		this.params = params;
		final ProfileParameters context = params.getContext();
		if (LOG.isInfoEnabled()) {
			LOG.info("====> Extending: " + (dssDocument.getName() == null ? "IN MEMORY DOCUMENT" : dssDocument.getName()));
		}
		documentDom = DSSXMLUtils.buildDOM(dssDocument);

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
			if (signatureId != null && !signatureId.equals(currentSignatureId)) {

				continue;
			}
			final CertificatePool certPool = new CertificatePool();
			// TODO-Bob (13/07/2014):  The XPath query holder can be inherited from the xadesSignature: to be analysed
			xadesSignature = new XAdESSignature(currentSignatureDom, certPool);
			xadesSignature.setDetachedContents(params.getDetachedContent());
			extendSignatureTag();
		}
		final byte[] documentBytes = DSSXMLUtils.serializeNode(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}

	/**
	 * Extends the signature to a desired level. This method is overridden by other profiles.<br>
	 * For -T profile adds the SignatureTimeStamp element which contains a single HashDataInfo element that refers to the
	 * ds:SignatureValue element of the [XMLDSIG] signature. The timestamp token is obtained from TSP source.<br>
	 * Adds <SignatureTimeStamp> segment into <UnsignedSignatureProperties> element.
	 *
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	protected void extendSignatureTag() throws DSSException {

		assertExtendSignaturePossible();

		// We ensure that all XML segments needed for the construction of the extension -T are present.
		// If a segment does not exist then it is created.
		ensureUnsignedProperties();
		ensureUnsignedSignatureProperties();
		ensureSignedDataObjectProperties();

		// The timestamp must be added only if there is no one or the extension -T level is being created
		if (!xadesSignature.hasTProfile() || XAdES_BASELINE_T.equals(params.getSignatureLevel())) {

			final TimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			final String canonicalizationMethod = signatureTimestampParameters.getCanonicalizationMethod();
			final byte[] canonicalisedValue = xadesSignature.getSignatureTimestampData(null, canonicalizationMethod);
			final DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
			final byte[] digestValue = DSSUtils.digest(timestampDigestAlgorithm, canonicalisedValue);
			createXAdESTimeStampType(SIGNATURE_TIMESTAMP, canonicalizationMethod, digestValue);
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignaturePossible() throws DSSException {

		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (XAdES_BASELINE_T.equals(signatureLevel) && (xadesSignature.hasLTProfile() || xadesSignature.hasLTAProfile())) {

			final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
			throw new DSSException(String.format(exceptionMessage, "XAdES LT"));
		}
	}

	/**
	 * Sets the TSP source to be used when extending the digital signature
	 *
	 * @param tspSource the tspSource to set
	 */
	public void setTspSource(final TSPSource tspSource) {

		this.tspSource = tspSource;
	}

	/**
	 * This method incorporates all certificates used during the validation process. if any certificate is already present within the KeyInfo then it is
	 * ignored.
	 *
	 * @param parentDom
	 * @param valContext
	 */
	protected void incorporateCertificateValues(final Element parentDom, final ValidationContext valContext) {

		// <xades:CertificateValues>
		// ...<xades:EncapsulatedX509Certificate>MIIC9TC...

		final Element certificateValuesDom = DSSXMLUtils.addElement(documentDom, parentDom, XAdES, XADES_CERTIFICATE_VALUES);

		final Set<CertificateToken> certificatesForInclusionInProfileLT = xadesSignature.getCertificatesForInclusion(valContext);

		final CertificatePool certificatePool = getCertificatePool();
		final boolean trustAnchorBPPolicy = params.bLevel().isTrustAnchorBPPolicy();
		boolean trustAnchorIncluded = false;
		for (final CertificateToken certificateToken : certificatesForInclusionInProfileLT) {

			if (trustAnchorBPPolicy && certificatePool != null) {

				final List<CertificateToken> certificateTokens = certificatePool.get(certificateToken.getSubjectX500Principal());
				if (certificateTokens.size() > 0) {
					trustAnchorIncluded = true;
				}
			}
			final byte[] bytes = certificateToken.getEncoded();
			final String base64EncodeCertificate = DSSUtils.base64Encode(bytes);
			DSSXMLUtils.addTextElement(documentDom, certificateValuesDom, XAdES, XADES_ENCAPSULATED_X509_CERTIFICATE, base64EncodeCertificate);
		}
		if (trustAnchorBPPolicy && !trustAnchorIncluded) {
			LOG.warn("The trust anchor is missing but its inclusion is required by the signature policy!");
		}
	}

	/**
	 * Creates any XAdES TimeStamp object representation. The timestamp token is obtained from TSP source
	 *
	 * @param timestampType       {@code TimestampType}
	 * @param timestampC14nMethod canonicalization method
	 * @param digestValue         array of {@code byte} representing the digest to timestamp
	 * @throws DSSException in case of any error
	 */
	protected void createXAdESTimeStampType(final TimestampType timestampType, final String timestampC14nMethod, final byte[] digestValue) throws DSSException {

		try {

			Element timeStampDom = null;
			final TimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
			switch (timestampType) {

				case SIGNATURE_TIMESTAMP:
					// <xades:SignatureTimeStamp Id="time-stamp-1dee38c4-8388-40d1-8880-9eeda853fe60">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES, XADES_SIGNATURE_TIME_STAMP);
					break;
				case VALIDATION_DATA_REFSONLY_TIMESTAMP:
					// timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, XADES_);
					break;
				case VALIDATION_DATA_TIMESTAMP:
					// <xades:SigAndRefsTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES, XADES_SIG_AND_REFS_TIME_STAMP);
					break;
				case ARCHIVE_TIMESTAMP:
					// <xades141:ArchiveTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdES141, XADES141_ARCHIVE_TIME_STAMP);
					timestampDigestAlgorithm = params.getArchiveTimestampParameters().getDigestAlgorithm();
					break;
				case ALL_DATA_OBJECTS_TIMESTAMP:
					timeStampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_ALL_DATA_OBJECTS_TIME_STAMP);
					break;
				case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
					timeStampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_INDIVIDUAL_DATA_OBJECTS_TIME_STAMP);
					break;
			}

			if (LOG.isDebugEnabled()) {

				final String encodedDigestValue = DSSUtils.base64Encode(digestValue);
				LOG.debug("Timestamp generation: " + timestampDigestAlgorithm.getName() + " / " + timestampC14nMethod + " / " + encodedDigestValue);
			}
			final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digestValue);
			final byte[] timeStampTokenBytes = timeStampToken.getEncoded();
			final String base64EncodedTimeStampToken = DSSUtils.base64Encode(timeStampTokenBytes);

			final String signatureTimestampId = UUID.randomUUID().toString();
			timeStampDom.setAttribute(ID, "TS-" + signatureTimestampId);

			// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
			incorporateC14nMethod(timeStampDom, timestampC14nMethod);

			// <xades:EncapsulatedTimeStamp Id="time-stamp-token-6a150419-caab-4615-9a0b-6e239596643a">MIAGCSqGSIb3DQEH
			final Element encapsulatedTimeStampDom = DSSXMLUtils.addElement(documentDom, timeStampDom, XAdES, XADES_ENCAPSULATED_TIME_STAMP);
			encapsulatedTimeStampDom.setAttribute(ID, "ETS-" + signatureTimestampId);
			DSSXMLUtils.setTextNode(documentDom, encapsulatedTimeStampDom, base64EncodedTimeStampToken);
		} catch (IOException e) {
			throw new DSSException("Error during the creation of the XAdES timestamp!", e);
		}
	}
}
