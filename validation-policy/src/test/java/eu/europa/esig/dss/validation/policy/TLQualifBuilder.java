package eu.europa.esig.dss.validation.policy;

public class TLQualifBuilder {

	private TLQualifBuilder() {
	}

	public static TLQualification getNoCAQC() {
		TLQualification tlQualif = new TLQualification();
		return tlQualif;
	}

	public static TLQualification getCAQC() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		return tlQualif;
	}

	public static TLQualification getCAQcWithQcSSCD() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcWithSSCD(true);
		return tlQualif;
	}

	public static TLQualification getCAQcSSCDandQcStat() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcWithSSCD(true);
		tlQualif.setQcStatement(true);
		return tlQualif;
	}

	public static TLQualification getCAQcWithQcNoSSCD() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcCNoSSCD(true);
		return tlQualif;
	}

	public static TLQualification getCAQcSSCDAsInCert() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcSSCDAsInCert(true);
		return tlQualif;
	}

	public static TLQualification getCAQcForLegalPerson() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcForLegalPerson(true);
		return tlQualif;
	}

	public static TLQualification getCAQcNoSSCDandQcStat() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcCNoSSCD(true);
		tlQualif.setQcStatement(true);
		return tlQualif;
	}

	public static TLQualification getCAQcSSCDAsInCertAndQcStat() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcSSCDAsInCert(true);
		tlQualif.setQcStatement(true);
		return tlQualif;
	}

	public static TLQualification getCAQcForLegalPersonAndQcStat() {
		TLQualification tlQualif = new TLQualification();
		tlQualif.setCaqc(true);
		tlQualif.setQcForLegalPerson(true);
		tlQualif.setQcStatement(true);
		return tlQualif;
	}

}
