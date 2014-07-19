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

package eu.europa.ec.markt.dss.validation102853.processes.dss;

import java.util.List;

import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.rules.RuleConstant;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class checks if the signer's certificate used in validating the signature is mandated to be issued by a
 * certificate authority issuing certificate as having been issued to a legal person.
 *
 * @author bielecro
 */
public class ForLegalPerson implements NodeName, NodeValue, AttributeName, AttributeValue, RuleConstant {

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
	 * <p/>
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
		return qualifiers.contains(QC_FOR_LEGAL_PERSON) || qualifiers.contains(QC_FOR_LEGAL_PERSON_119612);
	}
}
