package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessDefinition;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.SignatureIntactCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.checks.ProspectiveCertificateChainCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.LatestRevocationAcceptanceCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationAcceptanceCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationConsistentCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.AcceptableRevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.IdPkixOcspNoCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

public class RevocationAcceptanceChecker extends Chain<XmlRAC> {

	private final CertificateWrapper certificate;
	private final CertificateRevocationWrapper revocationData;
	private final Date controlTime;
	private final ValidationPolicy policy;
	
	private final List<String> validatedTokens;
	
	private POEExtraction poe; // optional

	public RevocationAcceptanceChecker(I18nProvider i18nProvider, CertificateWrapper certificate, CertificateRevocationWrapper revocationData,
			Date controlTime, ValidationPolicy policy) {
		this(i18nProvider, certificate, revocationData, controlTime, null, policy);
	}

	public RevocationAcceptanceChecker(I18nProvider i18nProvider, CertificateWrapper certificate, CertificateRevocationWrapper revocationData,
			Date controlTime, POEExtraction poe, ValidationPolicy policy) {
		this(i18nProvider, certificate, revocationData, controlTime, poe, policy, new ArrayList<String>());
		result.setId(revocationData.getId());
		result.setTitle(ValidationProcessDefinition.RAV.getTitle());
		result.setRevocationProductionDate(revocationData.getProductionDate());
	}
	
	private RevocationAcceptanceChecker(I18nProvider i18nProvider, CertificateWrapper certificate, CertificateRevocationWrapper revocationData,
			Date controlTime, POEExtraction poe, ValidationPolicy policy, List<String> validatedTokens) {
		super(i18nProvider, new XmlRAC());
		this.certificate = certificate;
		this.revocationData = revocationData;
		this.controlTime = controlTime;
		this.poe = poe;
		this.policy = policy;
		this.validatedTokens = validatedTokens;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlRAC> item = firstItem = revocationDataConsistent();
		
		item = item.setNextItem(revocationDataIntact());
		
		item = item.setNextItem(prospectiveCertificateChain(revocationData.getSigningCertificate()));
		
		for (CertificateWrapper revocationCertificate : revocationData.getCertificateChain()) {
			
			if (revocationCertificate.isTrusted()) {
				break;
			}
			
			if (isTokenValidated(revocationCertificate)) {
				continue;
			}
			
			item = item.setNextItem(certificateIntact(revocationCertificate));
			
			if (!ValidationProcessUtils.isRevocationNoNeedCheck(revocationCertificate, getValidationTime(revocationCertificate))) {
				SubContext subContext = revocationData.getSigningCertificate().getId().equals(revocationCertificate.getId()) ? 
						SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
				
				item = item.setNextItem(revocationDataPresent(revocationCertificate, subContext));
				
				CertificateRevocationWrapper latestRevocationData = null;
				XmlRAC latestRacResult = null;
				for (CertificateRevocationWrapper revocationWrapper : revocationCertificate.getCertificateRevocationData()) {
					
					if (isTokenValidated(revocationWrapper)) {
						if (latestRevocationData == null || 
								revocationWrapper.getProductionDate().before(latestRevocationData.getProductionDate())) {
							latestRevocationData = revocationWrapper;
						}
						continue;
					}
					
					RevocationAcceptanceChecker rac = revocationAcceptanceChecker(revocationCertificate, revocationWrapper);
					XmlRAC racResult = rac.execute();
					
					item = item.setNextItem(revocationAcceptanceResultCheck(racResult));
					
					if (isValid(racResult) && (latestRevocationData == null || 
							revocationWrapper.getProductionDate().after(latestRevocationData.getProductionDate()))) {
						latestRevocationData = revocationWrapper;
						latestRacResult = racResult;
					}
					
				}
				
				item = item.setNextItem(acceptableRevocationDataAvailable(latestRevocationData, revocationCertificate, subContext));
				
				if (latestRacResult != null) {
					item = item.setNextItem(latestRevocationAcceptable(latestRacResult));
				}
				
			} else {
				item = item.setNextItem(idPkixOcspNoCheck());
				
			}
			
		}
		
	}

	private ChainItem<XmlRAC> revocationDataConsistent() {
		return new RevocationConsistentCheck<XmlRAC>(i18nProvider, result, certificate, revocationData, getFailLevelConstraint());
	}
	
	private ChainItem<XmlRAC> revocationDataIntact() {
		LevelConstraint constraint = policy.getSignatureIntactConstraint(Context.REVOCATION);
		return new SignatureIntactCheck<XmlRAC>(i18nProvider, result, revocationData, Context.REVOCATION, constraint);
	}

	private ChainItem<XmlRAC> prospectiveCertificateChain(CertificateWrapper signingCertificate) {
		LevelConstraint constraint = policy.getProspectiveCertificateChainConstraint(Context.REVOCATION);
		return new ProspectiveCertificateChainCheck<XmlRAC>(i18nProvider, result, signingCertificate, Context.REVOCATION, constraint);
	}
	
	private boolean isTokenValidated(TokenProxy token) {
		boolean validated = validatedTokens.contains(token.getId());
		validatedTokens.add(token.getId());
		return validated;
	}
	
	private ChainItem<XmlRAC> certificateIntact(CertificateWrapper certificate) {
		LevelConstraint constraint = policy.getSignatureIntactConstraint(Context.CERTIFICATE);
		return new SignatureIntactCheck<XmlRAC>(i18nProvider, result, certificate, Context.CERTIFICATE, constraint);
	}

	private ChainItem<XmlRAC> idPkixOcspNoCheck() {
		return new IdPkixOcspNoCheck<XmlRAC>(i18nProvider, result, getFailLevelConstraint());
	}
	
	private ChainItem<XmlRAC> revocationDataPresent(CertificateWrapper certificate, SubContext subContext) {
		LevelConstraint constraint = policy.getRevocationDataAvailableConstraint(Context.REVOCATION, subContext);
		return new RevocationDataAvailableCheck<XmlRAC>(i18nProvider, result, certificate, constraint) {

			@Override
			protected String getAdditionalInfo() {
				String additionalInfo = super.getAdditionalInfo();
				if (certificate.isIdPkixOcspNoCheck() && !certificate.isRevocationDataAvailable()) {
					additionalInfo = String.format("The validation time '%s' is out of validity range of the certificate '%s'", 
							convertDate(getValidationTime(certificate)), certificate.getId());
				}
				return additionalInfo;
			}
			
		};
	}
	
	private Date getValidationTime(TokenProxy token) {
		if (poe == null) {
			return controlTime;
		}
		return poe.getLowestPOETime(token.getId(), controlTime);
	}
	
	private RevocationAcceptanceChecker revocationAcceptanceChecker(CertificateWrapper certificateWrapper, CertificateRevocationWrapper revocationWrapper) {
		return new RevocationAcceptanceChecker(i18nProvider, certificateWrapper, revocationWrapper, controlTime, poe, policy, validatedTokens);
	}
	
	private ChainItem<XmlRAC> revocationAcceptanceResultCheck(XmlRAC racResult) {
		return new RevocationAcceptanceCheckerResultCheck<XmlRAC>(i18nProvider, result, racResult, getWarnLevelConstraint());
	}
	
	private ChainItem<XmlRAC> latestRevocationAcceptable(XmlRAC racResult) {
		return new LatestRevocationAcceptanceCheckerResultCheck<XmlRAC>(i18nProvider, result, racResult, getFailLevelConstraint());
	}

	private ChainItem<XmlRAC> acceptableRevocationDataAvailable(RevocationWrapper revocationData, 
			CertificateWrapper certificateWrapper, SubContext subContext) {
		LevelConstraint constraint = policy.getRevocationDataAvailableConstraint(Context.REVOCATION, subContext);
		return new AcceptableRevocationDataAvailableCheck<XmlRAC>(i18nProvider, result, certificateWrapper, revocationData, constraint);
	}

}
