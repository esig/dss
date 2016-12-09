package eu.europa.esig.dss.validation.policy;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.validation.reports.SignatureType;

/**
 * Unit tests based on the_strength_of_the_signature.png
 *
 */
public class SignatureQualificationTest {

	@Test
	public void testTLwithCAQC() {
		// QCP
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQC()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQC()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQC()));

		// QCP+
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQC()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQC()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQC()));

		// QCC
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQC()));

		// QcSSCD
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQC()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQC()));

		// No qualif
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQC()));
	}

	@Test
	public void testTLwithCAQcWithSSCD() {
		// QCP
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcWithQcSSCD()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcWithQcSSCD()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcWithQcSSCD()));

		// QCP+
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcWithQcSSCD()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcWithQcSSCD()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcWithQcSSCD()));

		// QCC
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcWithQcSSCD()));

		// QcSSCD
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcWithQcSSCD()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcWithQcSSCD()));

		// No qualif
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcWithQcSSCD()));
	}

	@Test
	public void testTLwithCAQcWithQcNoSSCD() {
		// QCP
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcWithQcNoSSCD()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcWithQcNoSSCD()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcWithQcNoSSCD()));

		// QCP+
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcWithQcNoSSCD()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcWithQcNoSSCD()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcWithQcNoSSCD()));

		// QCC
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcWithQcNoSSCD()));

		// QcSSCD
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcWithQcNoSSCD()));

		// QCC + QcSSCD
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcWithQcNoSSCD()));

		// No qualif
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcWithQcNoSSCD()));
	}

	@Test
	public void testTLwithCAQcSSCDAsInCert() {
		// QCP
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcSSCDAsInCert()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcSSCDAsInCert()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcSSCDAsInCert()));

		// QCP+
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcSSCDAsInCert()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcSSCDAsInCert()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcSSCDAsInCert()));

		// QCC
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcSSCDAsInCert()));

		// QcSSCD
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcSSCDAsInCert()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcSSCDAsInCert()));

		// No qualif
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcSSCDAsInCert()));
	}

	@Test
	public void testTLwithCAQcForLegalPerson() {
		// QCP
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcForLegalPerson()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcForLegalPerson()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcForLegalPerson()));

		// QCP+
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcForLegalPerson()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcForLegalPerson()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcForLegalPerson()));

		// QCC
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcForLegalPerson()));

		// QcSSCD
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcForLegalPerson()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcForLegalPerson()));

		// No qualif
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcForLegalPerson()));
	}

	@Test
	public void testTLwithCAQcWithSSCDandQcStatement() {
		// QCP
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcSSCDandQcStat()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcSSCDandQcStat()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcSSCDandQcStat()));

		// QCP+
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcSSCDandQcStat()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcSSCDandQcStat()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcSSCDandQcStat()));

		// QCC
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcSSCDandQcStat()));

		// QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcSSCDandQcStat()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcSSCDandQcStat()));

		// No qualif
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcSSCDandQcStat()));
	}

	@Test
	public void testTLwithCAQcWithQcNoSSCDandQcStatement() {
		// QCP
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));

		// QCP+
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));

		// QCC
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));

		// QcSSCD
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));

		// QCC + QcSSCD
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));

		// No qualif
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcNoSSCDandQcStat()));
	}

	@Test
	public void testTLwithCAQcSSCDAsInCertAndQcStatement() {
		// QCP
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));

		// QCP+
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));

		// QCC
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));

		// QcSSCD
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));

		// No qualif
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcSSCDAsInCertAndQcStat()));
	}

	@Test
	public void testTLwithCAQcForLegalPersonAndQcStatement() {
		// QCP
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));

		// QCP+
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));

		// QCC
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));

		// QcSSCD
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES,
				SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));

		// No qualif
		assertEquals(SignatureType.AdESqc,
				SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getCAQcForLegalPersonAndQcStat()));
	}

	@Test
	public void testTLNotCoveredByCAQC() {
		// QCP
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpOnly(), TLQualifBuilder.getNoCAQC()));
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQcc(), TLQualifBuilder.getNoCAQC()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcpQccQcsscd(), TLQualifBuilder.getNoCAQC()));

		// QCP+
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppOnly(), TLQualifBuilder.getNoCAQC()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcc(), TLQualifBuilder.getNoCAQC()));
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcppQcsscd(), TLQualifBuilder.getNoCAQC()));

		// QCC
		assertEquals(SignatureType.AdESqc, SignatureQualification.getSignatureType(CertQualifBuilder.getQccOnly(), TLQualifBuilder.getNoCAQC()));

		// QcSSCD
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getQcsscdOnly(), TLQualifBuilder.getNoCAQC()));

		// QCC + QcSSCD
		assertEquals(SignatureType.QES, SignatureQualification.getSignatureType(CertQualifBuilder.getQccQcsscd(), TLQualifBuilder.getNoCAQC()));

		// No qualif
		assertEquals(SignatureType.AdES, SignatureQualification.getSignatureType(CertQualifBuilder.getNoQualif(), TLQualifBuilder.getNoCAQC()));
	}

}
