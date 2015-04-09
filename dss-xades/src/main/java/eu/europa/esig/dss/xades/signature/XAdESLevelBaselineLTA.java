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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.TimestampParameters;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * Holds level LTA aspects of XAdES
 *
 */
public class XAdESLevelBaselineLTA extends XAdESLevelBaselineLT {

	/**
	 * The default constructor for XAdESLevelBaselineLTA.
	 */
	public XAdESLevelBaselineLTA(final CertificateVerifier certVerifier) {

		super(certVerifier);
	}

	/**
	 * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the TSA
	 * (messageImprint) is computed on the XAdES-LT form of the electronic signature and the signed data objects.<br>
	 *
	 * A XAdES-LTA form MAY contain several ArchiveTimeStamp elements.
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		// check if -LT is present
		super.extendSignatureTag();
		if (xadesSignature.hasLTAProfile()) {

			checkSignatureIntegrity();

			final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

			removeLastTimestampValidationData();
			incorporateTimestampValidationData(validationContext);
		}

		incorporateArchiveTimestamp();
	}

	/**
	 * This method removes the timestamp validation data of the las archive timestamp.
	 */
	private void removeLastTimestampValidationData() {

		final Element toRemove = xadesSignature.getLastTimestampValidationData();
		if (toRemove != null) {

			unsignedSignaturePropertiesDom.removeChild(toRemove);
		}
	}

	/**
	 * This method incorporates the timestamp validation data in the signature
	 *
	 * @param validationContext
	 */
	private void incorporateTimestampValidationData(final ValidationContext validationContext) {

		final Element timeStampValidationDataDom = DSSXMLUtils
				.addElement(documentDom, unsignedSignaturePropertiesDom, XAdESNamespaces.XAdES141, "xades141:TimeStampValidationData");

		final Set<CertificateToken> toIncludeSetOfCertificates = xadesSignature.getCertificatesForInclusion(validationContext);
		final List<CertificateToken> toIncludeCertificates = new ArrayList<CertificateToken>();
		toIncludeCertificates.addAll(toIncludeSetOfCertificates);
		incorporateCertificateValues(timeStampValidationDataDom, toIncludeCertificates);

		incorporateRevocationValues(timeStampValidationDataDom, validationContext);
		String id = "1";
		final List<TimestampToken> archiveTimestamps = xadesSignature.getArchiveTimestamps();
		if (archiveTimestamps.size() > 0) {

			final TimestampToken timestampToken = archiveTimestamps.get(archiveTimestamps.size() - 1);
			id = "" + timestampToken.getDSSId();
		}

		timeStampValidationDataDom.setAttribute("Id", "id-" + id);
	}

	/**
	 * This method incorporate timestamp type object.
	 */
	private void incorporateArchiveTimestamp() {

		final TimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		final String canonicalizationMethod = archiveTimestampParameters.getCanonicalizationMethod();
		final byte[] archiveTimestampData = xadesSignature.getArchiveTimestampData(null, canonicalizationMethod);
		final DigestAlgorithm timestampDigestAlgorithm = archiveTimestampParameters.getDigestAlgorithm();
		final byte[] digestBytes = DSSUtils.digest(timestampDigestAlgorithm, archiveTimestampData);
		createXAdESTimeStampType(TimestampType.ARCHIVE_TIMESTAMP, canonicalizationMethod, digestBytes);
	}
}
