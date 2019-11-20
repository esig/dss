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
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlSimpleTimestampReport;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlTimestampQualification;
import eu.europa.esig.dss.utils.Utils;

public class SimpleReportForTimestampBuilder {

	private final DiagnosticData diagnosticData;
	private final DetailedReport detailedReport;
	private final Date currentTime;
	private final String timestampId;

	public SimpleReportForTimestampBuilder(DiagnosticData diagnosticData, DetailedReport detailedReport, Date currentTime, String timestampId) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.currentTime = currentTime;
		this.timestampId = timestampId;
	}

	public XmlSimpleTimestampReport build() {
		XmlSimpleTimestampReport simpleReport = new XmlSimpleTimestampReport();
		simpleReport.setValidationTime(currentTime);
		
		TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampId);
		
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setId(timestampId);
		xmlTimestamp.setProductionTime(timestampWrapper.getProductionTime());
		xmlTimestamp.setProducedBy(getProducedByName(timestampWrapper));
		xmlTimestamp.setCertificateChain(getCertificateChain(timestampWrapper));
		
		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);
		xmlTimestamp.setIndication(timestampBBB.getConclusion().getIndication());
		xmlTimestamp.setSubIndication(timestampBBB.getConclusion().getSubIndication());
		xmlTimestamp.getErrors().addAll(toStrings(timestampBBB.getConclusion().getErrors()));
		xmlTimestamp.getWarnings().addAll(toStrings(timestampBBB.getConclusion().getWarnings()));
		xmlTimestamp.getInfos().addAll(toStrings(timestampBBB.getConclusion().getInfos()));
		
		// TODO : qualification
		xmlTimestamp.setTimestampQualification(XmlTimestampQualification.N_A);
		
		simpleReport.setTimestamp(xmlTimestamp);
		return simpleReport;
	}
	
	private String getProducedByName(TimestampWrapper timestampWrapper) {
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getReadableCertificateName();
		}
		return Utils.EMPTY_STRING;
	}
	
	private List<XmlCertificate> getCertificateChain(TimestampWrapper timestampWrapper) {
		List<XmlCertificate> xmlCertificateChain = new ArrayList<XmlCertificate>();
		List<CertificateWrapper> certificateChain = timestampWrapper.getCertificateChain();
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			for (CertificateWrapper cert : certificateChain) {
				XmlCertificate certificate = new XmlCertificate();
				certificate.setId(cert.getId());
				certificate.setQualifiedName(cert.getReadableCertificateName());
				xmlCertificateChain.add(certificate);
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
