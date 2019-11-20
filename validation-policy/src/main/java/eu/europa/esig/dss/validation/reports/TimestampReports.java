package eu.europa.esig.dss.validation.reports;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simpletimestampreport.SimpleTimestampReport;
import eu.europa.esig.dss.simpletimestampreport.SimpleTimestampReportFacade;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlSimpleTimestampReport;

public class TimestampReports extends AbstractReports {

	private final SimpleTimestampReport simpleReportWrapper;
	private String xmlSimpleReport;

	/**
	 * This is the default constructor to instantiate this container.
	 *
	 * @param diagnosticDataJaxb
	 *                           the JAXB {@code XmlDiagnosticData}
	 * @param detailedReport
	 *                           the JAXB {@code XmlDetailedReport}
	 * @param simpleReport
	 *                           the JAXB {@code XmlSimpleTimestampReport}
	 */
	public TimestampReports(final XmlDiagnosticData diagnosticDataJaxb, final XmlDetailedReport detailedReport,
			final XmlSimpleTimestampReport simpleReport) {
		super(diagnosticDataJaxb, detailedReport);
		this.simpleReportWrapper = new SimpleTimestampReport(simpleReport);
	}

	/**
	 * This method returns the wrapper to manipulate the JAXB
	 * SimpleTimestampReport
	 *
	 * @return the wrapper {@code SimpleTimestampReport}
	 */
	public SimpleTimestampReport getSimpleReport() {
		return simpleReportWrapper;
	}

	/**
	 * This method returns the JAXB XmlSimpleTimestampReport
	 * 
	 * @return the JAXB {@code XmlSimpleTimestampReport}
	 */
	public XmlSimpleTimestampReport getSimpleReportJaxb() {
		return simpleReportWrapper.getJaxbModel();
	}

	/**
	 * This method returns the XML representation of the JAXB
	 * XmlSimpleTimestampReport String
	 * 
	 * @return a String with the XML content of the JAXB
	 *         {@code XmlSimpleTimestampReport}
	 * @throws DSSReportException - in case of marshalling error
	 */
	@Override
	public String getXmlSimpleReport() throws DSSReportException {
		try {
			if (xmlSimpleReport == null) {
				xmlSimpleReport = SimpleTimestampReportFacade.newFacade().marshall(getSimpleReportJaxb(), validateXml);
			}
			return xmlSimpleReport;
		} catch (JAXBException | IOException | SAXException e) {
			throw new DSSReportException("An error occurred during marshalling of JAXB Simple Timestamp Report", e);
		}
	}

}
