package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampQualification;
import eu.europa.esig.dss.simplereport.jaxb.XmlValidationPolicy;
import eu.europa.esig.dss.utils.Utils;

public class SimpleReportForTimestampBuilder {

	private final DiagnosticData diagnosticData;
	private final DetailedReport detailedReport;
	private final Date currentTime;
	private final ValidationPolicy policy;

	public SimpleReportForTimestampBuilder(DiagnosticData diagnosticData, DetailedReport detailedReport, Date currentTime, ValidationPolicy policy) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.currentTime = currentTime;
		this.policy = policy;
	}

	public XmlSimpleReport build() {
		XmlSimpleReport simpleReport = new XmlSimpleReport();
		
		addValidationTime(simpleReport);
		addPolicyNode(simpleReport);
		addTimestamps(simpleReport);
		
		return simpleReport;
	}
	
	private void addValidationTime(XmlSimpleReport report) {
		report.setValidationTime(currentTime);
	}

	private void addPolicyNode(XmlSimpleReport report) {
		XmlValidationPolicy xmlpolicy = new XmlValidationPolicy();
		xmlpolicy.setPolicyName(policy.getPolicyName());
		xmlpolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setValidationPolicy(xmlpolicy);
	}
	
	private void addTimestamps(XmlSimpleReport report) {
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampWrapper timestampWrapper : timestamps) {
				report.getSignatureOrTimestamp().add(getXmlTimestamp(timestampWrapper));
			}
		}
	}
	
	private XmlTimestamp getXmlTimestamp(TimestampWrapper timestampWrapper) {
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setId(timestampWrapper.getId());
		xmlTimestamp.setProductionTime(timestampWrapper.getProductionTime());
		xmlTimestamp.setProducedBy(getProducedByName(timestampWrapper));
		xmlTimestamp.setCertificateChain(getCertificateChain(timestampWrapper));
		xmlTimestamp.setFilename(timestampWrapper.getFilename());
		
		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampWrapper.getId());
		xmlTimestamp.setIndication(timestampBBB.getConclusion().getIndication());
		xmlTimestamp.setSubIndication(timestampBBB.getConclusion().getSubIndication());
		xmlTimestamp.getErrors().addAll(toStrings(timestampBBB.getConclusion().getErrors()));
		xmlTimestamp.getWarnings().addAll(toStrings(timestampBBB.getConclusion().getWarnings()));
		xmlTimestamp.getInfos().addAll(toStrings(timestampBBB.getConclusion().getInfos()));
		
		// TODO : qualification
		xmlTimestamp.setTimestampQualification(XmlTimestampQualification.N_A);
		
		return xmlTimestamp;
	}
	
	private String getProducedByName(TimestampWrapper timestampWrapper) {
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getReadableCertificateName();
		}
		return Utils.EMPTY_STRING;
	}
	
	private XmlCertificateChain getCertificateChain(TimestampWrapper timestampWrapper) {
		XmlCertificateChain xmlCertificateChain = new XmlCertificateChain();
		List<CertificateWrapper> certificateChain = timestampWrapper.getCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			for (CertificateWrapper cert : certificateChain) {
				XmlCertificate certificate = new XmlCertificate();
				certificate.setId(cert.getId());
				certificate.setQualifiedName(cert.getReadableCertificateName());
				xmlCertificateChain.getCertificate().add(certificate);
			}
		}
		return xmlCertificateChain;
	}
	
	private List<String> toStrings(List<XmlName> xmlNames) {
		List<String> strings = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(xmlNames)) {
			for (XmlName name : xmlNames) {
				strings.add(name.getValue());
			}
		}
		return strings;
	}

}
