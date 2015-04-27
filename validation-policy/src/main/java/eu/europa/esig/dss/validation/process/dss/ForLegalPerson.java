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
 * This class checks if the signer's certificate used in validating the signature is mandated to be issued by a
 * certificate authority issuing certificate as having been issued to a legal person.
 *
 *
 */
public class ForLegalPerson {

	private ValidationPolicy constraintData;

	/**
	 * The default constructor with the policy object.
	 *
	 * @param constraintData
	 */
	public ForLegalPerson(final ValidationPolicy constraintData) {

		super();
		this.constraintData = constraintData;
	}

	/**
	 * The ForLegalPerson constraint is to be applied to the signer's certificate of the main signature or of the
	 * timestamp before considering it as valid for the intended use.
	 *
	 * // @param isTimestamp indicates if this is a timestamp signing cert or main signature signing cert.
	 *
	 * @param cert the cert to be processed
	 * @return
	 */
	public Boolean run(final XmlDom cert) {

		return process(cert);
	}

	/**
	 * Generalised implementation independent of the context (SigningCertificate or TimestampSigningCertificate).
	 *
	 * @param cert the cert to be processed
	 * @return
	 */
	private boolean process(final XmlDom cert) {

		final List<String> qualifiers = InvolvedServiceInfo.getQualifiers(cert);

		/**
		 * Mandates the signer's certificate used in validating the signature to be issued by a certificate authority
		 * issuing certificate as having been issued to a legal person.
		 */
		return qualifiers.contains(TSLConstant.QC_FOR_LEGAL_PERSON) || qualifiers.contains(TSLConstant.QC_FOR_LEGAL_PERSON_119612);
	}
}
