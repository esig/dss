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
package eu.europa.esig.dss.validation.process.bbb.xcv;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.CheckSubXCVResult;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustedServiceStatusCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.TrustedServiceTypeIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.SubX509CertificateValidation;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.Model;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.6 X.509 certificate validation
 * 
 * This building block validates the signing certificate at current time.
 */
public class X509CertificateValidation extends Chain<XmlXCV> {

	private final DiagnosticData diagnosticData;
	private final CertificateWrapper currentCertificate;
	private final Date validationDate;
	private final Date usageTime;

	private final Context context;
	private final ValidationPolicy validationPolicy;

	public X509CertificateValidation(DiagnosticData diagnosticData, CertificateWrapper currentCertificate, Date validationDate, Context context,
			ValidationPolicy validationPolicy) {
		this(diagnosticData, currentCertificate, validationDate, validationDate, context, validationPolicy);
	}

	public X509CertificateValidation(DiagnosticData diagnosticData, CertificateWrapper currentCertificate, Date validationDate, Date usageTime, Context context,
			ValidationPolicy validationPolicy) {
		super(new XmlXCV());

		this.diagnosticData = diagnosticData;
		this.currentCertificate = currentCertificate;
		this.validationDate = validationDate;
		this.usageTime = usageTime;

		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlXCV> item = firstItem = prospectiveCertificateChain();

		if (currentCertificate.isTrusted() || currentCertificate.isTrustedChain()) {

			item = item.setNextItem(trustedServiceWithExpectedTypeIdentifier());

			item = item.setNextItem(trustedServiceWithExpectedStatus());

			SubX509CertificateValidation certificateValidation = new SubX509CertificateValidation(currentCertificate, validationDate, context,
					SubContext.SIGNING_CERT, validationPolicy);
			XmlSubXCV subXCV = certificateValidation.execute();
			result.getSubXCV().add(subXCV);

			boolean trustAnchorReached = currentCertificate.isTrusted();

			final Model model = validationPolicy.getValidationModel();

			// Check CA_CERTIFICATEs
			Date lastDate = Model.SHELL.equals(model) ? validationDate : currentCertificate.getNotBefore();
			List<XmlChainItem> certificateChainList = currentCertificate.getCertificateChain();
			if (Utils.isCollectionNotEmpty(certificateChainList)) {
				for (XmlChainItem chainCertificate : certificateChainList) {
					if (!trustAnchorReached) {
						CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(chainCertificate.getId());
						certificateValidation = new SubX509CertificateValidation(certificate, lastDate, context, SubContext.CA_CERTIFICATE, validationPolicy);
						subXCV = certificateValidation.execute();
						result.getSubXCV().add(subXCV);

						trustAnchorReached = certificate.isTrusted();
						lastDate = Model.HYBRID.equals(model) ? lastDate : (Model.SHELL.equals(model) ? validationDate : certificate.getNotBefore());
					}
				}
			}

			for (XmlSubXCV subXCVresult : result.getSubXCV()) {
				item = item.setNextItem(checkSubXCVResult(subXCVresult));
			}
		}
	}

	private ChainItem<XmlXCV> prospectiveCertificateChain() {
		LevelConstraint constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
		return new ProspectiveCertificateChainCheck(result, currentCertificate, context, constraint);
	}

	private ChainItem<XmlXCV> trustedServiceWithExpectedTypeIdentifier() {
		MultiValuesConstraint constraint = validationPolicy.getTrustedServiceTypeIdentifierConstraint(context);
		return new TrustedServiceTypeIdentifierCheck(result, currentCertificate, usageTime, context, constraint);
	}

	private ChainItem<XmlXCV> trustedServiceWithExpectedStatus() {
		MultiValuesConstraint constraint = validationPolicy.getTrustedServiceStatusConstraint(context);
		return new TrustedServiceStatusCheck(result, currentCertificate, usageTime, context, constraint);
	}

	private ChainItem<XmlXCV> checkSubXCVResult(XmlSubXCV subXCVresult) {
		return new CheckSubXCVResult(result, subXCVresult, getFailLevelConstraint());
	}
	
}
