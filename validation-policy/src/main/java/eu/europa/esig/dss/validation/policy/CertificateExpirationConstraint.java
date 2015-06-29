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
package eu.europa.esig.dss.validation.policy;

import java.util.Date;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;
import eu.europa.esig.dss.validation.report.Conclusion;

/**
 * This class represents a signing certificate validity constraints. The validation is composed of:
 * - check of the validity range compared to the current time.
 * - check of the field: ExpiredCertsRevocationInfo in the trusted list.
 */
public class CertificateExpirationConstraint extends Constraint {

	/**
	 * This variable stores the notAfter field of the signing certificate.
	 */
	protected Date notAfter;

	/**
	 * This variable stores the notBefore field of the signing certificate.
	 */
	protected Date notBefore;

	/**
	 * This variable stores the ExpiredCertsRevocationInfo extension from the trusted service associated to the certificate.
	 */
	protected Date expiredCertsRevocationInfo;

	/**
	 * This is the See {@link eu.eu.europa.esig.dss.validation.policy.ProcessParameters#getCurrentTime()}
	 */
	protected Date currentTime;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public CertificateExpirationConstraint(final String level) {

		super(level);
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(final Date notAfter) {
		this.notAfter = notAfter;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(final Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

	public void setExpiredCertsRevocationInfo(final Date expiredCertsRevocationInfo) {
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	public Date getCurrentTime() {
		return currentTime;
	}

	public void setCurrentTime(final Date currentTime) {
		this.currentTime = currentTime;
	}

	/**
	 * This method carry out the validation of the constraint.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	@Override
	public boolean check() {

		if (ignore()) {

			node.addChild(NodeName.STATUS, NodeValue.IGNORED);
			return true;
		}
		if (inform()) {

			node.addChild(NodeName.STATUS, NodeValue.INFORMATION);
			node.addChild(NodeName.INFO, null, messageAttributes).setAttribute("ExpectedValue", expectedValue).setAttribute("ConstraintValue", value);
			return true;
		}
		final boolean certValidity = (currentTime.compareTo(notBefore) >= 0) && (currentTime.compareTo(notAfter) <= 0);
		if ((expiredCertsRevocationInfo == null) && !certValidity) {

			final String formatedNotBefore = DSSUtils.formatDate(notBefore);
			final String formatedNotAfter = DSSUtils.formatDate(notAfter);
			if (warn()) {

				node.addChild(NodeName.STATUS, NodeValue.WARN);
				node.addChild(NodeName.WARNING, failureMessageTag, messageAttributes);
				final Conclusion.Warning warning = conclusion.addWarning(failureMessageTag, messageAttributes);
				warning.setAttribute(AttributeValue.NOT_BEFORE, formatedNotBefore);
				warning.setAttribute(AttributeValue.NOT_AFTER, formatedNotAfter);
				return true;
			}
			node.addChild(NodeName.STATUS, NodeValue.KO);
			node.addChild(NodeName.ERROR, failureMessageTag, messageAttributes);
			conclusion.setIndication(indication, subIndication);
			final Conclusion.Error error = conclusion.addError(failureMessageTag, messageAttributes);
			error.setAttribute(AttributeValue.NOT_BEFORE, formatedNotBefore);
			error.setAttribute(AttributeValue.NOT_AFTER, formatedNotAfter);
			return false;
		}
		node.addChild(NodeName.STATUS, NodeValue.OK);
		if (messageAttributes.size() > 0) {
			node.addChild(NodeName.INFO, null, messageAttributes);
		}
		if (expiredCertsRevocationInfo != null) {

			final String formatedExpiredCertsRevocationInfo = DSSUtils.formatDate(expiredCertsRevocationInfo);
			node.addChild(NodeName.INFO).setAttribute(AttributeValue.EXPIRED_CERTS_REVOCATION_INFO, formatedExpiredCertsRevocationInfo);
		}
		return true;
	}
}

