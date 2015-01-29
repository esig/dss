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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.XAdESNamespaces;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.ValidationContext;

/**
 * Holds level A aspects of XAdES
 *
 * @version $Revision$ - $Date$
 */

public class XAdESLevelBaselineLTA extends XAdESLevelBaselineLT {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelBaselineLTA.class);

	/**
	 * The default constructor for XAdESLevelBaselineLTA.
	 */
	public XAdESLevelBaselineLTA(final CertificateVerifier certVerifier) {

		super(certVerifier);
	}

	/**
	 * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the TSA
	 * (messageImprint) is computed on the XAdES-LT form of the electronic signature and the signed data objects.<br>
	 * <p/>
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
		final List toIncludeCertificates = new ArrayList();
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
