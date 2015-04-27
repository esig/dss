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
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;

/**
 * A.2 Constraints on X.509 Certificate meta-data
 *
 * The QualifiedCertificate constraint is to be applied to the signer's certificate before considering it as valid for
 * the intended use.
 *
 *
 */
public class QualifiedCertificate {

	private ValidationPolicy constraintData;

	/**
	 * The default constructor with the policy object.
	 *
	 * @param constraintData
	 */
	public QualifiedCertificate(final ValidationPolicy constraintData) {

		super();
		this.constraintData = constraintData;
	}

	/**
	 * The QualifiedCertificate constraint is to be applied to the main signature or timestamp signer's certificate
	 * before considering it as valid for the intended use.
	 *
	 * //@param isTimestamp indicates if this is a timestamp signing certificate or main signature signing certificate.
	 *
	 * @param cert the certificate to be processed
	 * @return
	 */
	public boolean run(final XmlDom cert) {

		return process(cert);
	}

	/**
	 * Generalised implementation independent of the context (SigningCertificate or TimestampSigningCertificate).
	 *
	 * @param certificate The certificate to be processed
	 * @return
	 */
	private boolean process(final XmlDom certificate) {

		if (certificate == null) {
			return false;
		}

		/**
		 * Mandates the signer's certificate used in validating the signature to be a qualified certificate as defined in
		 * Directive 1999/93/EC [9]. This status can be derived from:
		 */

		/**
		 * • QcCompliance extension being set in the signer's certificate in accordance with TS 101 862 [5];
		 */

		final boolean isQCC = certificate.getBoolValue("./QCStatement/QCC/text()");

		/**
		 * • QCP+ or QCP certificate policy OID being indicated in the signer's certificate policies extension (i.e.
		 * 0.4.0.1456.1.1 or 0.4.0.1456.1.2);
		 */

		final boolean isQCP = certificate.getBoolValue("./QCStatement/QCP/text()");

		final boolean isQCPPlus = certificate.getBoolValue("./QCStatement/QCPPlus/text()");

		/**
		 * • The content of a Trusted service Status List;<br>
		 * • The content of a Trusted List through information provided in the Sie field of the applicable service entry;
		 */

		final List<String> qualifiers = InvolvedServiceInfo.getQualifiers(certificate);
		final boolean isSIE = qualifiers.contains(TSLConstant.QC_STATEMENT) || qualifiers.contains(TSLConstant.QC_STATEMENT_119612);

		/**
		 * or • Static configuration that provides such information in a trusted manner.
		 */

		// --> Not implemented

		return isQCC || isQCP || isQCPPlus || isSIE;
	}
}