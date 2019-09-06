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
package eu.europa.esig.dss.validation.process.bbb.isc;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.detailedreport.jaxb.XmlChainItem;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.DigestValueMatchCheck;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.DigestValuePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.IssuerSerialMatchCheck;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.SigningCertificateAttributePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.SigningCertificateRecognitionCheck;

/**
 * 5.2.3 Identification of the signing certificate
 * This building block is responsible for identifying the signing certificate that will be used to validate the
 * signature.
 */
public class IdentificationOfTheSigningCertificate extends Chain<XmlISC> {

	private final TokenProxy token;

	private final Context context;
	private final ValidationPolicy validationPolicy;

	public IdentificationOfTheSigningCertificate(TokenProxy token, Context context, ValidationPolicy validationPolicy) {
		super(new XmlISC());
		result.setTitle(BasicBuildingBlockDefinition.IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE.getTitle());

		this.token = token;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {

		/*
		 * The common way to unambiguously identify the signing certificate is by using a property/attribute of the
		 * signature containing a reference to it (see clause 4.2.5.2). The certificate can either be found in the
		 * signature or it can be obtained using external sources. The signing certificate can also be provided by the
		 * DA. If no certificate can be retrieved, the building block shall return the indication INDETERMINATE and the
		 * sub-indication NO_SIGNING_CERTIFICATE_FOUND.
		 */
		ChainItem<XmlISC> item = firstItem = signingCertificateRecognition();

		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context)) {
			/*
			 * 1) If the signature format used contains a way to directly identify the reference to the signers'
			 * certificate in the attribute, the building block shall check that the digest of the certificate
			 * referenced matches the result of digesting the signing certificate with the algorithm indicated; if they
			 * match, the building block shall return the signing certificate. Otherwise, the building block shall go to
			 * step 2.
			 */

			// PKCS7 signatures have not these information
			SignatureWrapper signature = (SignatureWrapper) token;
			if (signature.getSignatureFormat() != null && SignatureForm.PKCS7.equals(signature.getSignatureFormat().getSignatureForm())) {
				return;
			}

			item = item.setNextItem(signingCertificateAttributePresent());

			/*
			 * 2) The building block shall take the first reference and shall check that the digest of the certificate
			 * referenced matches the result of digesting the signing certificate with the algorithm indicated. If they
			 * do not match, the building block shall take the next element and shall repeat this step until a matching
			 * element has been found or all elements have been checked. If they do match, the building block shall
			 * continue with step 3. If the last element is reached without finding any match, the validation of this
			 * property shall be taken as failed and the building block shall return the indication INDETERMINATE with
			 * the sub-indication NO_SIGNING_CERTIFICATE_FOUND.
			 */
			item = item.setNextItem(digestValuePresent());
			item = item.setNextItem(digestValueMatch());

			/*
			 * 3) If the issuer and the serial number are additionally present in that reference, the details of the
			 * issuer's name and the serial number of the IssuerSerial element may be compared with those indicated in
			 * the signing certificate: if they do not match, an additional warning shall be returned with the output.
			 */
			item = item.setNextItem(issuerSerialMatch());
		}
	}

	@Override
	protected void addAdditionalInfo() {
		super.addAdditionalInfo();

		if (token.getCertificateChain() != null) {
			XmlCertificateChain certificateChain = new XmlCertificateChain();
			for (CertificateWrapper certificate : token.getCertificateChain()) {
				XmlChainItem chainItem = new XmlChainItem();
				chainItem.setId(certificate.getId());
				List<CertificateSourceType> sources = certificate.getSources();
				if (sources.contains(CertificateSourceType.TRUSTED_LIST)) {
					chainItem.setSource(CertificateSourceType.TRUSTED_LIST);
				} else if (sources.contains(CertificateSourceType.TRUSTED_STORE)) {
					chainItem.setSource(CertificateSourceType.TRUSTED_STORE);
				} else {
					chainItem.setSource(sources.iterator().next());
				}
				certificateChain.getChainItem().add(chainItem);
			}
			result.setCertificateChain(certificateChain);
		}
	}

	private ChainItem<XmlISC> signingCertificateRecognition() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateRecognitionConstraint(context);
		return new SigningCertificateRecognitionCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> signingCertificateAttributePresent() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateAttributePresentConstraint(context);
		return new SigningCertificateAttributePresentCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> digestValuePresent() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateDigestValuePresentConstraint(context);
		return new DigestValuePresentCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> digestValueMatch() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateDigestValueMatchConstraint(context);
		return new DigestValueMatchCheck(result, token, constraint);
	}

	private ChainItem<XmlISC> issuerSerialMatch() {
		LevelConstraint constraint = validationPolicy.getSigningCertificateIssuerSerialMatchConstraint(context);
		return new IssuerSerialMatchCheck(result, token, constraint);
	}

}
