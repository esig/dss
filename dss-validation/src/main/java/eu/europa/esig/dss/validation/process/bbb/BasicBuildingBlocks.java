/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanCertificateTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.aov.AlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.CertificateAndChainAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.AttestationAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.AttestationRevocationAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.RevocationDataAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.SignatureAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.aov.TimestampAlgorithmObsolescenceValidation;
import eu.europa.esig.dss.validation.process.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.validation.process.bbb.fc.AttestationFormatChecking;
import eu.europa.esig.dss.validation.process.bbb.fc.AttestationRevocationFormatChecking;
import eu.europa.esig.dss.validation.process.bbb.fc.SignatureFormatChecking;
import eu.europa.esig.dss.validation.process.bbb.fc.TimestampFormatChecking;
import eu.europa.esig.dss.validation.process.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.validation.process.bbb.sav.AbstractAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.AttestationAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.AttestationRevocationTokenAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.RevocationAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.TimestampAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.vci.ValidationContextInitialization;
import eu.europa.esig.dss.validation.process.bbb.xcv.X509CertificateValidation;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 5.2 Basic building blocks
 */
public class BasicBuildingBlocks {

	/** i18nProvider */
	private final I18nProvider i18nProvider;

	/** Diagnostic Data */
	private final DiagnosticData diagnosticData;

	/** The validating token */
	private final TokenProxy token;

	/** The validation policy */
	private final ValidationPolicy policy;

	/** Map of baic building blocks */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** The validation time */
	private final Date currentTime;

	/** The validation context */
	private final Context context;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param token {@link TokenProxy} to validate
	 * @param currentTime {@link Date} validation time
	 * @param bbbs a map of {@link XmlBasicBuildingBlocks}
	 * @param policy {@link ValidationPolicy}
	 * @param context {@link Context}
	 */
	public BasicBuildingBlocks(I18nProvider i18nProvider, DiagnosticData diagnosticData, TokenProxy token,
							   Date currentTime, Map<String, XmlBasicBuildingBlocks> bbbs, ValidationPolicy policy,
							   Context context) {
		this.i18nProvider = i18nProvider;
		this.diagnosticData = diagnosticData;
		this.token = token;
		this.currentTime = currentTime;
		this.bbbs = bbbs;
		this.policy = policy;
		this.context = context;
	}

	/**
	 * Executes 5.2 token validation process
	 *
	 * @return {@link XmlBasicBuildingBlocks}
	 */
	public XmlBasicBuildingBlocks execute() {
		XmlBasicBuildingBlocks result = new XmlBasicBuildingBlocks();
		result.setId(token.getId());
		result.setType(context);
		result.setConclusion(new XmlConclusion());

		/*
		 * 5.2.2 Format Checking
		 */
		XmlFC fc = executeFormatChecking();
		if (fc != null) {
			result.setFC(fc);
			updateFinalConclusion(result, fc);
		}

		/*
		 * 5.2.3 Identification of the signing certificate
		 */
		XmlISC isc = executeIdentificationOfTheSigningCertificate();
		if (isc != null) {
			result.setISC(isc);
			result.setCertificateChain(isc.getCertificateChain());
			updateFinalConclusion(result, isc);
		}

		/*
		 * 5.2.4 Validation context initialization (only for signature)
		 */
		XmlVCI vci = executeValidationContextInitialization();
		if (vci != null) {
			result.setVCI(vci);
			updateFinalConclusion(result, vci);
		}

		/*
		 * Algorithm Obsolescence Validation
		 * NOTE: out of standard, but executed to receive a harmonized input for 5.2.6 and 5.2.8 building blocks
		 */
		XmlAOV aov = executeAlgorithmObsolescenceValidation();
		if (aov != null) {
			result.setAOV(aov);
		}

		/*
		 * 5.2.6 X.509 certificate validation
		 */
		XmlXCV xcv = executeX509CertificateValidation(aov);
		if (xcv != null) {
			result.setXCV(xcv);
			addAdditionalInfo(xcv);
			updateFinalConclusion(result, xcv);
		}

		/*
		 * 5.2.7 Cryptographic verification
		 */
		XmlCV cv = executeCryptographicVerification();
		if (cv != null) {
			result.setCV(cv);
			updateFinalConclusion(result, cv);
		}

		/*
		 * 5.2.8 Signature acceptance validation (SAV)
		 */
		XmlSAV sav = executeSignatureAcceptanceValidation(aov);
		if (sav != null) {
			result.setSAV(sav);
			updateFinalConclusion(result, sav);
		}

		if (result.getConclusion().getIndication() == null) {
			result.getConclusion().setIndication(Indication.PASSED);
		}

		return result;
	}

	private void updateFinalConclusion(XmlBasicBuildingBlocks result, XmlConstraintsConclusion constraintsAndConclusion) {
		XmlConclusion finalConclusion = result.getConclusion();

		XmlConclusion currentConclusion = constraintsAndConclusion.getConclusion();
		if (!Indication.PASSED.equals(currentConclusion.getIndication())) {
			finalConclusion.setIndication(currentConclusion.getIndication());
			finalConclusion.setSubIndication(currentConclusion.getSubIndication());
			finalConclusion.getErrors().addAll(currentConclusion.getErrors());
		}
		finalConclusion.getWarnings().addAll(currentConclusion.getWarnings());
		finalConclusion.getInfos().addAll(currentConclusion.getInfos());
	}

	private XmlFC executeFormatChecking() {
		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context) || Context.KEY_BINDING_SIGNATURE.equals(context)) {
			SignatureFormatChecking fc = new SignatureFormatChecking(i18nProvider, diagnosticData, (SignatureWrapper) token, context, policy);
			return fc.execute();
		} else if (Context.TIMESTAMP.equals(context)) {
			TimestampFormatChecking fc = new TimestampFormatChecking(i18nProvider, diagnosticData, (TimestampWrapper) token, context, policy);
			XmlFC xmlFC = fc.execute();
			if (Utils.isCollectionNotEmpty(xmlFC.getConstraint())) {
				return xmlFC;
			}
		} else if (Context.ATTESTATION.equals(context)) {
			AttestationFormatChecking fc = new AttestationFormatChecking(i18nProvider, diagnosticData, (AttestationWrapper) token, context, policy);
			return fc.execute();
		} else if (Context.ATTESTATION_REVOCATION.equals(context)) {
			AttestationRevocationFormatChecking fc = new AttestationRevocationFormatChecking(i18nProvider, diagnosticData, (AttestationRevocationTokenWrapper) token, context, policy);
			return fc.execute();
		}
		return null;
	}

	private XmlISC executeIdentificationOfTheSigningCertificate() {
		if (!Context.CERTIFICATE.equals(context) && !Context.ATTESTATION.equals(context)) {
			IdentificationOfTheSigningCertificate isc = new IdentificationOfTheSigningCertificate(i18nProvider, token, context, policy);
			return isc.execute();
		} else {
			return null;
		}
	}

	private XmlVCI executeValidationContextInitialization() {
		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context) || Context.KEY_BINDING_SIGNATURE.equals(context)) {
			ValidationContextInitialization vci = new ValidationContextInitialization(i18nProvider, (SignatureWrapper) token, context, policy);
			return vci.execute();
		}
		return null;
	}

	private XmlAOV executeAlgorithmObsolescenceValidation() {
		AlgorithmObsolescenceValidation<?> aov = null;
		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context) || Context.KEY_BINDING_SIGNATURE.equals(context)) {
			aov = new SignatureAlgorithmObsolescenceValidation<>(
					i18nProvider, (SignatureWrapper) token, context, currentTime, policy);
		} else if (Context.TIMESTAMP.equals(context)) {
			aov = new TimestampAlgorithmObsolescenceValidation(
					i18nProvider, (TimestampWrapper) token, currentTime, policy);
		} else if (Context.REVOCATION.equals(context)) {
			aov = new RevocationDataAlgorithmObsolescenceValidation(
					i18nProvider, (RevocationWrapper) token, currentTime, policy);
		} else if (Context.CERTIFICATE.equals(context)) {
			aov = new CertificateAndChainAlgorithmObsolescenceValidation(
					i18nProvider, (CertificateWrapper) token, context, currentTime, policy);
		} else if (Context.ATTESTATION.equals(context)) {
			aov = new AttestationAlgorithmObsolescenceValidation(
					i18nProvider, (AttestationWrapper) token, currentTime, policy);
		} else if (Context.ATTESTATION_REVOCATION.equals(context)) {
			aov = new AttestationRevocationAlgorithmObsolescenceValidation(
					i18nProvider, (AttestationRevocationTokenWrapper) token, currentTime, policy);
		}
		return aov != null ? aov.execute() : null;
	}

	private XmlXCV executeX509CertificateValidation(XmlAOV aov) {
		X509CertificateValidation x509CertificateValidation = getX509CertificateValidation(aov);
		if (x509CertificateValidation != null) {
			return x509CertificateValidation.execute();
		}
		return null;
	}
	
	private X509CertificateValidation getX509CertificateValidation(XmlAOV aov) {
		if (Context.CERTIFICATE.equals(context)) {
			CertificateWrapper certificate = (CertificateWrapper) token;
			return new X509CertificateValidation(i18nProvider, certificate, currentTime,
					certificate.getNotBefore(), context, aov, policy);

		} else {
			CertificateWrapper signingCertificate = token.getSigningCertificate();
			if (signingCertificate != null) {
				if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context) || Context.KEY_BINDING_SIGNATURE.equals(context)) {
					return new X509CertificateValidation(i18nProvider, signingCertificate, currentTime,
							signingCertificate.getNotBefore(), context, aov, policy);

				} else if (Context.TIMESTAMP.equals(context)) {
					return new X509CertificateValidation(i18nProvider, signingCertificate, currentTime,
							((TimestampWrapper) token).getProductionTime(), context, aov, policy);

				} else if (Context.REVOCATION.equals(context)) {
					return new X509CertificateValidation(i18nProvider, signingCertificate, currentTime,
							((RevocationWrapper) token).getProductionDate(), context, aov, policy);

				} else if (Context.ATTESTATION_REVOCATION.equals(context)) {
					return new X509CertificateValidation(i18nProvider, signingCertificate, currentTime,
							((AttestationRevocationTokenWrapper) token).getIssuedAt(), context, aov, policy);
				}
			}
		}
		return null;
	}
	
	private void addAdditionalInfo(XmlXCV xcv) {
		for (XmlSubXCV subXCV : xcv.getSubXCV()) {
			CertificateWrapper cert = diagnosticData.getUsedCertificateById(subXCV.getId());
			List<CertificateWrapper> crossCertificates = diagnosticData.getCrossCertificates(cert);
			if (Utils.isCollectionNotEmpty(crossCertificates)) {
				subXCV.getCrossCertificates().addAll(getCertificateWrapperIds(crossCertificates));
			}
			List<OrphanCertificateTokenWrapper> orphanCrossCertificates = diagnosticData.getOrphanCrossCertificates(cert);
			if (Utils.isCollectionNotEmpty(orphanCrossCertificates)) {
				subXCV.getCrossCertificates().addAll(getOrphanCertificateWrapperIds(orphanCrossCertificates));
			}

			List<CertificateWrapper> equivalentCertificates = diagnosticData.getEquivalentCertificates(cert);
			equivalentCertificates.removeAll(crossCertificates);
			if (Utils.isCollectionNotEmpty(equivalentCertificates)) {
				subXCV.getEquivalentCertificates().addAll(getCertificateWrapperIds(equivalentCertificates));
			}
			List<OrphanCertificateTokenWrapper> orphanEquivalentCertificates = diagnosticData.getOrphanEquivalentCertificates(cert);
			orphanEquivalentCertificates.removeAll(orphanCrossCertificates);
			if (Utils.isCollectionNotEmpty(orphanEquivalentCertificates)) {
				subXCV.getEquivalentCertificates().addAll(getOrphanCertificateWrapperIds(orphanEquivalentCertificates));
			}
		}
	}
	
	/**
	 * Returns a list of token ids
	 * 
	 * @param tokens a collection of tokens to get ids from
	 * @return a list of {@link String} ids
	 */
	private static List<String> getCertificateWrapperIds(Collection<CertificateWrapper> tokens) {
		return tokens.stream().map(TokenProxy::getId).collect(Collectors.toList());
	}

	/**
	 * Returns a list of orphan token ids
	 *
	 * @param tokens a collection of tokens to get ids from
	 * @return a list of {@link String} ids
	 */
	private static List<String> getOrphanCertificateWrapperIds(Collection<OrphanCertificateTokenWrapper> tokens) {
		return tokens.stream().map(OrphanCertificateTokenWrapper::getId).collect(Collectors.toList());
	}

	private XmlCV executeCryptographicVerification() {
		if (!Context.CERTIFICATE.equals(context)) {
			CryptographicVerification cv = new CryptographicVerification(i18nProvider, diagnosticData, token, context, policy);
			return cv.execute();
		} else {
			return null;
		}
	}

	private XmlSAV executeSignatureAcceptanceValidation(XmlAOV aov) {
		AbstractAcceptanceValidation<?> aav = null;
		if (Context.SIGNATURE.equals(context) || Context.COUNTER_SIGNATURE.equals(context) || Context.KEY_BINDING_SIGNATURE.equals(context)) {
			aav = new SignatureAcceptanceValidation(
					i18nProvider, diagnosticData, currentTime, (SignatureWrapper) token, context, bbbs, aov, policy);
		} else if (Context.TIMESTAMP.equals(context)) {
			aav = new TimestampAcceptanceValidation(i18nProvider, currentTime, (TimestampWrapper) token, aov, policy);
		} else if (Context.REVOCATION.equals(context)) {
			aav = new RevocationAcceptanceValidation(i18nProvider, currentTime, (RevocationWrapper) token, aov, policy);
		} else if (Context.ATTESTATION.equals(context)) {
			aav = new AttestationAcceptanceValidation(i18nProvider, currentTime, (AttestationWrapper) token, bbbs, aov, policy);
		} else if (Context.ATTESTATION_REVOCATION.equals(context)) {
			aav = new AttestationRevocationTokenAcceptanceValidation(i18nProvider, currentTime, (AttestationRevocationTokenWrapper) token, aov, policy);
		}
		return aav != null ? aav.execute() : null;
	}

}
