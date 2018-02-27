package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.QCStatementOids;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class TypeByCertificatePostEIDASTest {

	@Test
	public void esig() {

		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatementOids.QC_COMPLIANCE.getOid()),
				Arrays.asList(QCStatementOids.QCT_ESIGN.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.ESIGN, strategy.getType());
	}

	@Test
	public void esigDefault() {

		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatementOids.QC_COMPLIANCE.getOid()), Collections.<String> emptyList());
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.ESIGN, strategy.getType());
	}

	@Test
	public void eseal() {

		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatementOids.QC_COMPLIANCE.getOid()),
				Arrays.asList(QCStatementOids.QCT_ESEAL.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.ESEAL, strategy.getType());
	}

	@Test
	public void wsa() {
		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatementOids.QC_COMPLIANCE.getOid()),
				Arrays.asList(QCStatementOids.QCT_WEB.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.WSA, strategy.getType());
	}

	// MUST be overruled
	@Test
	public void multiple() {
		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatementOids.QC_COMPLIANCE.getOid()),
				Arrays.asList(QCStatementOids.QCT_ESIGN.getOid(), QCStatementOids.QCT_ESEAL.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.UNKNOWN, strategy.getType());
	}

	@Test
	public void noCompliance() {
		CertificateWrapper cert = new MockCertificateWrapper(Collections.<String> emptyList(), Arrays.asList(QCStatementOids.QCT_ESIGN.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.UNKNOWN, strategy.getType());
	}

	private class MockCertificateWrapper extends CertificateWrapper {

		private final List<String> qcStatementOids;
		private final List<String> qcTypesOids;

		public MockCertificateWrapper(List<String> qcStatementOids, List<String> qcTypesOids) {
			super(null);
			this.qcStatementOids = qcStatementOids;
			this.qcTypesOids = qcTypesOids;
		}

		@Override
		public List<String> getQCStatementIds() {
			return qcStatementOids;
		}

		@Override
		public List<String> getQCTypes() {
			return qcTypesOids;
		}

	}

}
