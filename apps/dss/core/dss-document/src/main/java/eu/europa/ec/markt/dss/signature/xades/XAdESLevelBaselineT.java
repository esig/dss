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
import java.util.Set;
import java.util.UUID;

import javax.xml.crypto.dsig.XMLSignature;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.XAdESNamespaces;
import eu.europa.ec.markt.dss.exception.DSSConfigurationException;
import eu.europa.ec.markt.dss.exception.DSSConfigurationException.MSG;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
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
		final Element canonicalizationMethodDom = documentDom.createElementNS(XMLSignature.XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodDom.setAttribute("Algorithm", signedInfoC14nMethod);
		parentDom.appendChild(canonicalizationMethodDom);
	}

	@Override
	public InMemoryDocument extendSignatures(final DSSDocument dssDocument, final SignatureParameters params) throws DSSException {

		if (dssDocument == null) {

			throw new DSSNullException(DSSDocument.class);
		}
		if (this.tspSource == null) {

			throw new DSSConfigurationException(MSG.CONFIGURE_TSP_SERVER);
		}
		this.params = params;
		final ProfileParameters context = params.getContext();

		if (LOG.isInfoEnabled()) {
			LOG.info("====> Extending: " + (dssDocument.getName() == null ? "IN MEMORY DOCUMENT" : dssDocument.getName()));
		}
		documentDom = DSSXMLUtils.buildDOM(dssDocument);

		final NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (signatureNodeList.getLength() == 0) {

			throw new DSSException("Impossible to perform the extension of the signature, the document is not signed.");
		}

		// In the case of the enveloped signature we have a specific treatment:<br>
		// we will just extend the signature that is being created (during creation process)
		String signatureId = null;
		final SignaturePackaging signaturePackaging = params.getSignaturePackaging();
		final Operation operationKind = context.getOperationKind();
		if (Operation.SIGNING.equals(operationKind) && SignaturePackaging.ENVELOPED.equals(signaturePackaging)) {

			signatureId = params.getDeterministicId();
		}
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			currentSignatureDom = (Element) signatureNodeList.item(ii);
			final String currentSignatureId = currentSignatureDom.getAttribute("Id");
			if (signatureId != null && !signatureId.equals(currentSignatureId)) {

				continue;
			}
			final CertificatePool certPool = new CertificatePool();
			// TODO-Bob (13/07/2014):  The XPath query holder can be inherited from the xadesSignature: to be analysed
			xadesSignature = new XAdESSignature(currentSignatureDom, certPool);
			xadesSignature.setDetachedContent(params.getDetachedContent());
			// In the cse of the extension of the signature the signing certificate must be included within the signature
			// xadesSignature.setProvidedSigningCertificateToken(null);
			extendSignatureTag();
		}
		final byte[] documentBytes = DSSXMLUtils.serializeNode(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
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

		// The timestamp must be added only if there is no one or the extension -T is being created
		if (!xadesSignature.hasTProfile() || SignatureLevel.XAdES_BASELINE_T.equals(params.getSignatureLevel())) {

			final byte[] canonicalisedValue = xadesSignature.getSignatureTimestampData(null);
			final DigestAlgorithm timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
			final byte[] digestValue = DSSUtils.digest(timestampDigestAlgorithm, canonicalisedValue);
			final String canonicalizationMethod = params.getSignatureTimestampParameters().getCanonicalizationMethod();
			createXAdESTimeStampType(TimestampType.SIGNATURE_TIMESTAMP, canonicalizationMethod, digestValue);
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignaturePossible() throws DSSException {

		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel) && (xadesSignature.hasLTProfile() || xadesSignature.hasLTAProfile())) {

			final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
			throw new DSSException(String.format(exceptionMessage, "XAdES LT"));
		}
	}

	/**
	 * Sets the TSP source to be used when extending the digital signature
	 *
	 * @param tspSource the tspSource to set
	 */
	public void setTspSource(TSPSource tspSource) {

		this.tspSource = tspSource;
	}

	/**
	 * This method incorporates all certificates used during the validation process. if any certificate is already present within the KeyInfo then it is
	 * ignored.
	 *
	 * @param parentDom
	 * @param valContext
	 */
	protected void incorporateCertificateValues(Element parentDom, final ValidationContext valContext) {

		// <xades:CertificateValues>
		// ...<xades:EncapsulatedX509Certificate>MIIC9TC...

		final Element certificateValuesDom = DSSXMLUtils.addElement(documentDom, parentDom, XAdESNamespaces.XAdES, "xades:CertificateValues");

		final Set<CertificateToken> certificatesForInclusionInProfileLT = xadesSignature.getCertificatesForInclusion(valContext);

		for (final CertificateToken certificateToken : certificatesForInclusionInProfileLT) {

			final byte[] bytes = certificateToken.getEncoded();
			final String base64EncodeCertificate = DSSUtils.base64Encode(bytes);
			DSSXMLUtils.addTextElement(documentDom, certificateValuesDom, XAdESNamespaces.XAdES, "xades:EncapsulatedX509Certificate", base64EncodeCertificate);
		}
	}

	/**
	 * Creates XAdES TimeStamp object representation. The time stamp token is obtained from TSP source
	 *
	 * @param timestampC14nMethod
	 * @param digestValue
	 * @return
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	protected void createXAdESTimeStampType(final TimestampType timestampType, final String timestampC14nMethod, final byte[] digestValue) throws DSSException {

		try {

			Element timeStampDom = null;
			DigestAlgorithm timestampDigestAlgorithm = null;
			switch (timestampType) {

				case SIGNATURE_TIMESTAMP:
					// <xades:SignatureTimeStamp Id="time-stamp-1dee38c4-8388-40d1-8880-9eeda853fe60">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SignatureTimeStamp");
					timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
					break;
				case VALIDATION_DATA_REFSONLY_TIMESTAMP:
					timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
					break;
				case VALIDATION_DATA_TIMESTAMP:
					// <xades:SigAndRefsTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES, "xades:SigAndRefsTimeStamp");
					timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
					break;
				case ARCHIVE_TIMESTAMP:
					// <xades141:ArchiveTimeStamp Id="time-stamp-a762ab0e-e05c-4cc8-a804-cf2c4ffb5516">
					timeStampDom = DSSXMLUtils.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES141, "xades141:ArchiveTimeStamp");
					timestampDigestAlgorithm = params.getArchiveTimestampParameters().getDigestAlgorithm();
					break;
				case CONTENT_TIMESTAMP:
					timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
					break;
				case ALL_DATA_OBJECTS_TIMESTAMP:
					timeStampDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, XAdESNamespaces.XAdES, "xades:AllDataObjectsTimeStamp");
					timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
					break;
				case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
					timeStampDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, XAdESNamespaces.XAdES, "xades:IndividualDataObjectsTimeStamp");
					timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
					break;
			}

			if (LOG.isInfoEnabled()) {

				final String encodedDigestValue = DSSUtils.base64Encode(digestValue);
				LOG.info("Timestamp generation: " + timestampDigestAlgorithm.getName() + " / " + timestampC14nMethod + " / " + encodedDigestValue);
			}
			final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digestValue);
			final byte[] timeStampTokenBytes = timeStampToken.getEncoded();

			final String signatureTimestampId = "time-stamp-token-" + UUID.randomUUID().toString();
			final String base64EncodedTimeStampToken = DSSUtils.base64Encode(timeStampTokenBytes);
			timeStampDom.setAttribute("Id", signatureTimestampId);

			// <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
			incorporateC14nMethod(timeStampDom, timestampC14nMethod);

			// <xades:EncapsulatedTimeStamp Id="time-stamp-token-6a150419-caab-4615-9a0b-6e239596643a">MIAGCSqGSIb3DQEH
			final Element encapsulatedTimeStampDom = DSSXMLUtils.addElement(documentDom, timeStampDom, XAdESNamespaces.XAdES, "xades:EncapsulatedTimeStamp");
			encapsulatedTimeStampDom.setAttribute("Id", signatureTimestampId);
			DSSXMLUtils.setTextNode(documentDom, encapsulatedTimeStampDom, base64EncodedTimeStampToken);
		} catch (IOException e) {

			throw new DSSException("Error during the creation of the XAdES timestamp!", e);
		}
	}

}
