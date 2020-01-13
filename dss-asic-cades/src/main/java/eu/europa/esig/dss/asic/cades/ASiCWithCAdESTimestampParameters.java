package eu.europa.esig.dss.asic.cades;

import java.util.Date;

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

@SuppressWarnings("serial")
public class ASiCWithCAdESTimestampParameters extends CAdESTimestampParameters implements ASiCWithCAdESCommonParameters {
	
	protected Date zipCreationDate = new Date();
	
	/**
	 * The object representing the parameters related to ASiC for the timestamp.
	 */
	private ASiCParameters asicParams = new ASiCParameters();

	public ASiCParameters aSiC() {
		return asicParams;
	}
	
	public ASiCWithCAdESTimestampParameters() {
	}

	public ASiCWithCAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}

	public ASiCWithCAdESTimestampParameters(DigestAlgorithm digestAlgorithm, ASiCParameters asicParams) {
		super(digestAlgorithm);
		this.asicParams = asicParams;
	}

	@Override
	public Date getZipCreationDate() {
		return zipCreationDate;
	}
	
	public void setZipCreationDate(Date zipCreationDate) {
		this.zipCreationDate = zipCreationDate;
	}

}
