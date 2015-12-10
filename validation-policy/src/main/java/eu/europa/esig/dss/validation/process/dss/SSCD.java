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
package eu.europa.esig.dss.validation.process.dss;

import java.util.List;

import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.report.DiagnosticDataWrapper;

/**
 * This class checks if the signing certificate is mandated to be supported by SSCD device.
 */
public class SSCD {

	private final ProcessParameters params;

	/**
	 * The default constructor with the policy object.
	 *
	 * @param constraintData
	 */
	public SSCD(final ProcessParameters params) {
		this.params = params;
	}

	/**
	 * The SSCD constraint is to be applied to the signer's certificate of the main signature or timestamp before
	 * considering it as valid for the intended use.
	 * // @param isTimestamp indicates if this is a timestamp signing certificate or main signature signing certificate.
	 *
	 * @param cert
	 *            the certificate to be processed
	 * @return
	 */
	public boolean run(final XmlCertificate cert) {
		return process(cert);
	}

	/**
	 * Generalised implementation independent of the context (SigningCertificate or TimestampSigningCertificate).
	 *
	 * @param certificate
	 *            the certificate to be processed
	 * @return
	 */
	private boolean process(final XmlCertificate certificate) {
		if (certificate == null) {
			return false;
		}
		/**
		 * Mandates the end user certificate used in validating the signature to be supported by a secure signature
		 * creation device (SSCD) as defined in Directive 1999/93/EC [9].
		 * This status is derived from: • QcSSCD extension being set in the signer's certificate in accordance with ETSI
		 * TS 101 862 [5];
		 */

		DiagnosticDataWrapper diagnosticData = params.getDiagnosticData();

		final boolean qcSSCD = diagnosticData.isCertificateQCSSCD(certificate);

		/**
		 * • QCP+ certificate policy OID being indicated in the signer's certificate policies extension (i.e.
		 * 0.4.0.1456.1.1);
		 */
		final boolean qcpPlus = diagnosticData.isCertificateQCPPlus(certificate);

		/**
		 * • The content of a Trusted service Status List;<br>
		 * • The content of a Trusted List through information provided in the Sie field of the applicable service entry;
		 * or
		 */

		final List<String> qualifiers = diagnosticData.getCertificateTSPServiceQualifiers(certificate);

		final boolean sie = qualifiers.contains(TSLConstant.QC_WITH_SSCD) || qualifiers.contains(TSLConstant.QC_WITH_SSCD_119612);
		// TODO To be clarified with Olivier D.
		//		|| qualifiers.contains(QCSSCD_STATUS_AS_IN_CERT) || qualifiers
		//			  .contains(QCSSCD_STATUS_AS_IN_CERT_119612);

		/**
		 * • Static configuration that provides such information in a trusted manner.
		 */
		// --> Not implemented

		if (!(qcSSCD || qcpPlus || sie)) {

			return false;
		}
		return true;
	}
}
