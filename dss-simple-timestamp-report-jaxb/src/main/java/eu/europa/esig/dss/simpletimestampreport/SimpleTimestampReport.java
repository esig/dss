package eu.europa.esig.dss.simpletimestampreport;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlSimpleTimestampReport;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlTimestampQualification;

/**
 * A wrapper class for JAXB {@code XmlSimpleTimestampReport}
 *
 */
public class SimpleTimestampReport {
	
	private final XmlSimpleTimestampReport simpleReport;
	
	public SimpleTimestampReport(XmlSimpleTimestampReport simpleTimestampReport) {
		this.simpleReport = simpleTimestampReport;
	}
	
	/**
	 * Returns JAXB {@code XmlSimpleTimestampReport}
	 * @return {@link XmlSimpleTimestampReport}
	 */
	public XmlSimpleTimestampReport getJaxbModel() {
		return simpleReport;
	}

	/**
	 * This method returns the used validation time
	 * 
	 * @return the validation time
	 */
	public Date getValidationTime() {
		return simpleReport.getValidationTime();
	}
	
	/**
	 * Returns Id of the validated timestamp
	 * @return {@link String} Id
	 */
	public String getTimestampId() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getId();
		}
		return null;
	}
	
	/**
	 * Returns a name of the issuer
	 * @return {@link String}
	 */
	public String getProducedBy() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getProducedBy();
		}
		return null;
	}
	
	/**
	 * Returns the timestamp production time
	 * @return {@link Date}
	 */
	public Date getProductionTime() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getProductionTime();
		}
		return null;
	}

	/**
	 * Returns the timestamp's certificate chain
	 * @return a list of {@link XmlCertificate}s
	 */
	public List<XmlCertificate> getCertificateChain() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getCertificateChain();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns ids of the timestamp's certificate chain
	 * @return a list of {@link String} ids
	 */
	public List<String> getCertificateChainIds() {
		List<String> ids = new ArrayList<String>();
		List<XmlCertificate> certificates = getCertificateChain();
		if (certificates != null) {
			for (XmlCertificate certificate : certificates) {
				ids.add(certificate.getId());
			}
		}
		return ids;
	}
	
	/**
	 * Returns the timestamp qualification
	 * @return {@link XmlTimestampQualification}
	 */
	public XmlTimestampQualification getTimestampQualification() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getTimestampQualification();
		}
		return null;
	}
	
	/**
	 * Returns the timestamp indication
	 * @return {@link Indication}
	 */
	public Indication getTimestampIndication() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getIndication();
		}
		return null;
	}
	
	/**
	 * Returns the timestamp subIndication
	 * @return {@link SubIndication}
	 */
	public SubIndication getTimestampSubIndication() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getSubIndication();
		}
		return null;
	}

	/**
	 * Returns the list of errors
	 * @return a list of {@link String} errors
	 */
	public List<String> getErrors() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getErrors();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the list of warnings
	 * @return a list of {@link String} warnings
	 */
	public List<String> getWarnings() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getWarnings();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the list of infos
	 * @return a list of {@link String} infos
	 */
	public List<String> getInfos() {
		if (simpleReport.getTimestamp() != null) {
			return simpleReport.getTimestamp().getInfos();
		}
		return Collections.emptyList();
	}
	
	/**
	 * Returns the validated timestamp
	 * @return {@link XmlTimestamp}
	 */
	public XmlTimestamp getTimestamp() {
		return simpleReport.getTimestamp();
	}

}
