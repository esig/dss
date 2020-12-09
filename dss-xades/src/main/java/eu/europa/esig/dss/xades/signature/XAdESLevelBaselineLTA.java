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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Set;

/**
 * Holds level LTA aspects of XAdES
 *
 */
public class XAdESLevelBaselineLTA extends XAdESLevelBaselineLT {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelBaselineLTA.class);

	/**
	 * The default constructor for XAdESLevelBaselineLTA.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public XAdESLevelBaselineLTA(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the
	 * TSA
	 * (messageImprint) is computed on the XAdES-LT form of the electronic signature and the signed data objects.<br>
	 *
	 * A XAdES-LTA form MAY contain several ArchiveTimeStamp elements.
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		// check if -LT is present
		super.extendSignatureTag();
		
		assertExtendSignatureToLTAPossible();
		
		Element levelLTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);
		if (xadesSignature.hasLTAProfile()) {

			checkSignatureIntegrity();

			// must be executed before data removing
			final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);
			String indent = removeLastTimestampValidationData();
			
			ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(validationContext);
			
			incorporateTimestampValidationData(validationDataForInclusion, indent);
		}

		incorporateArchiveTimestamp();
		
		unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelLTUnsignedProperties);
	}

	/**
	 * This method removes the timestamp validation data of the last archive timestamp.
	 * @return indent of the last {@code TimeStampValidationData} xml element, if present
	 */
	private String removeLastTimestampValidationData() {
		final Element toRemove = xadesSignature.getLastTimestampValidationData();
		if (toRemove != null) {
			/* Certificate and revocation sources need to be reset because of 
			 * the removing of timeStampValidationData element */
			xadesSignature.resetCertificateSource();
			xadesSignature.resetRevocationSources();
			
			return removeChild(unsignedSignaturePropertiesDom, toRemove);
		}
		return null;
	}

	/**
	 * This method incorporates the timestamp validation data in the signature
	 *
	 * @param validationDataForInclusion {@link ValidationDataForInclusion} to be included into the signature
	 */
	private void incorporateTimestampValidationData(final ValidationDataForInclusion validationDataForInclusion, String indent) {

		Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();
		
		if (Utils.isCollectionNotEmpty(certificateValuesToAdd) || Utils.isCollectionNotEmpty(crlsToAdd) || Utils.isCollectionNotEmpty(ocspsToAdd)) {
			
			final Element timeStampValidationDataDom = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, getXades141Namespace(),
					XAdES141Element.TIMESTAMP_VALIDATION_DATA);
			
			incorporateCertificateValues(timeStampValidationDataDom, certificateValuesToAdd, indent);
			incorporateRevocationValues(timeStampValidationDataDom, crlsToAdd, ocspsToAdd, indent);

			String id = "1";
			final List<TimestampToken> archiveTimestamps = xadesSignature.getArchiveTimestamps();
			if (archiveTimestamps.size() > 0) {
				final TimestampToken timestampToken = archiveTimestamps.get(archiveTimestamps.size() - 1);
				id = timestampToken.getDSSIdAsString();
			}

			timeStampValidationDataDom.setAttribute("Id", "id-" + id);
			if (params.isPrettyPrint()) {
				DSSXMLUtils.indentAndReplace(documentDom, timeStampValidationDataDom);
			}
			
		}
	}

	/**
	 * This method incorporate timestamp type object.
	 */
	private void incorporateArchiveTimestamp() {
		final XAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		final String canonicalizationMethod = archiveTimestampParameters.getCanonicalizationMethod();
		final byte[] archiveTimestampData = xadesSignature.getTimestampSource().getArchiveTimestampData(canonicalizationMethod);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Data to be signed by the ArchiveTimestamp:");
			LOG.trace(new String(archiveTimestampData));
		}
		final DigestAlgorithm timestampDigestAlgorithm = archiveTimestampParameters.getDigestAlgorithm();
		final byte[] digestBytes = DSSUtils.digest(timestampDigestAlgorithm, archiveTimestampData);
		createXAdESTimeStampType(TimestampType.ARCHIVE_TIMESTAMP, canonicalizationMethod, digestBytes);
	}

	private void assertExtendSignatureToLTAPossible() {
		if (SignatureLevel.XAdES_BASELINE_LTA.equals(params.getSignatureLevel())) {
			assertDetachedDocumentsContainBinaries();
		}
	}
	
	private void assertDetachedDocumentsContainBinaries() {
		List<DSSDocument> detachedContents = params.getDetachedContents();
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			for (DSSDocument detachedDocument : detachedContents) {
				if (detachedDocument instanceof DigestDocument) {
					throw new DSSException("XAdES-LTA requires complete binaries of signed documents! "
							+ "Extension with a DigestDocument is not possible.");
				}
			}
		}
	}
	
}
