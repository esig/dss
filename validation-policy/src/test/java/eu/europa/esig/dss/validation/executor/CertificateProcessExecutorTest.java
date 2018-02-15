package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlChainItem;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class CertificateProcessExecutorTest {

	@Test
	public void deRevoked() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/cert-validation/de_revoked.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		String certificateId = "0E9B5C373AFEC1CED5723FCD9231F793BB330FFBF2B94BB8698301C90405B9BF";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		DetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertNotNull(detailedReportJaxb);
		assertNotNull(detailedReportJaxb.getCertificate());
		assertEquals(2, detailedReportJaxb.getTLAnalysis().size());
		assertEquals(1, detailedReportJaxb.getBasicBuildingBlocks().size());
		assertEquals(0, detailedReportJaxb.getSignatures().size());

		SimpleCertificateReport simpleReportJaxb = reports.getSimpleReportJaxb();
		assertNotNull(simpleReportJaxb);
		assertNotNull(simpleReportJaxb.getChain());
		assertEquals(2, simpleReportJaxb.getChain().size());

		XmlChainItem cert = simpleReportJaxb.getChain().get(0);
		assertEquals(certificateId, cert.getId());
		assertNotNull(cert.getQualificationAtIssuance());
		assertNotNull(cert.getQualificationAtValidation());
		assertNull(cert.getTrustAnchors());

		XmlChainItem ca = simpleReportJaxb.getChain().get(1);
		assertNull(ca.getQualificationAtIssuance());
		assertNull(ca.getQualificationAtValidation());
		assertNotNull(ca.getTrustAnchors());

	}

	@Test
	public void beTSA() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/cert-validation/be_tsa.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		String certificateId = "D74AF393CF3B506DA33B46BC52B49CD6FAC12B2BDAA9CE1FBA25C0C1E4EBBE19";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		DetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertNotNull(detailedReportJaxb);
		assertNotNull(detailedReportJaxb.getCertificate());
		assertEquals(2, detailedReportJaxb.getTLAnalysis().size());
		assertEquals(1, detailedReportJaxb.getBasicBuildingBlocks().size());
		assertEquals(0, detailedReportJaxb.getSignatures().size());

		SimpleCertificateReport simpleReportJaxb = reports.getSimpleReportJaxb();
		assertNotNull(simpleReportJaxb);
		assertNotNull(simpleReportJaxb.getChain());
		assertEquals(2, simpleReportJaxb.getChain().size());

		XmlChainItem cert = simpleReportJaxb.getChain().get(0);
		assertEquals(certificateId, cert.getId());
		assertNotNull(cert.getQualificationAtIssuance());
		assertNotNull(cert.getQualificationAtValidation());
		assertNull(cert.getTrustAnchors());

		XmlChainItem ca = simpleReportJaxb.getChain().get(1);
		assertNull(ca.getQualificationAtIssuance());
		assertNull(ca.getQualificationAtValidation());
		assertNotNull(ca.getTrustAnchors());

	}

	@Test
	public void dkNoChain() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/cert-validation/dk_no_chain.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);

		String certificateId = "3ECBC4648AA3BCB671976F53D7516F774DB1C886FAB81FE5469462181187DB8D";

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(certificateId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();

		DetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertNotNull(detailedReportJaxb);
		assertNotNull(detailedReportJaxb.getCertificate());
		assertEquals(0, detailedReportJaxb.getTLAnalysis().size());
		assertEquals(1, detailedReportJaxb.getBasicBuildingBlocks().size());
		assertEquals(0, detailedReportJaxb.getSignatures().size());

		SimpleCertificateReport simpleReportJaxb = reports.getSimpleReportJaxb();
		assertNotNull(simpleReportJaxb);
		assertNotNull(simpleReportJaxb.getChain());
		assertEquals(1, simpleReportJaxb.getChain().size());

		XmlChainItem cert = simpleReportJaxb.getChain().get(0);
		assertEquals(certificateId, cert.getId());
		assertNotNull(cert.getQualificationAtIssuance());
		assertNotNull(cert.getQualificationAtValidation());
		assertNull(cert.getTrustAnchors());

	}

	private EtsiValidationPolicy loadPolicy() throws Exception {
		FileInputStream policyFis = new FileInputStream("src/main/resources/policy/constraint.xml");
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class, "/xsd/policy.xsd");
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

	@SuppressWarnings("unchecked")
	private <T extends Object> T getJAXBObjectFromString(InputStream is, Class<T> clazz, String xsd) throws Exception {
		JAXBContext context = JAXBContext.newInstance(clazz.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		if (Utils.isStringNotEmpty(xsd)) {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			InputStream inputStream = this.getClass().getResourceAsStream(xsd);
			Source source = new StreamSource(inputStream);
			Schema schema = sf.newSchema(source);
			unmarshaller.setSchema(schema);
		}
		return (T) unmarshaller.unmarshal(is);
	}

}
